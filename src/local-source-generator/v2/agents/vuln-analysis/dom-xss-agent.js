/**
 * DOMXSSAgent - DOM-based XSS detection agent
 * 
 * Detects client-side XSS vulnerabilities in modern Single Page Applications.
 * Analyzes JavaScript for dangerous sinks, tests hash/fragment injection,
 * and detects framework-specific XSS patterns.
 * 
 * CRITICAL FOR MODERN APPS - Server-side XSS tools miss client-side vulnerabilities.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class DOMXSSAgent extends BaseAgent {
    constructor(options = {}) {
        super('DOMXSSAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                jsFiles: {
                    type: 'array',
                    description: 'JavaScript files from JSHarvesterAgent',
                    items: { type: 'string' }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                dangerous_sinks: { type: 'array', items: { type: 'object' } },
                tested_endpoints: { type: 'number' },
            },
        };

        this.requires = {
            evidence_kinds: ['javascript_file', EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'dom_xss_detected',
                'dangerous_sink_found',
                'dom_xss_confirmed',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'dom_xss_vulnerable',
                'unsafe_dom_manipulation',
                'client_side_injection',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 180000, // 3 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Dangerous DOM sinks (sources of XSS)
        this.dangerousSinks = [
            // Direct execution
            { name: 'eval', pattern: /eval\s*\(/g, severity: 'critical' },
            { name: 'Function', pattern: /new\s+Function\s*\(/g, severity: 'critical' },
            { name: 'setTimeout(string)', pattern: /setTimeout\s*\(\s*["'`]/g, severity: 'high' },
            { name: 'setInterval(string)', pattern: /setInterval\s*\(\s*["'`]/g, severity: 'high' },
            
            // DOM manipulation
            { name: 'innerHTML', pattern: /\.innerHTML\s*=/g, severity: 'high' },
            { name: 'outerHTML', pattern: /\.outerHTML\s*=/g, severity: 'high' },
            { name: 'insertAdjacentHTML', pattern: /\.insertAdjacentHTML\s*\(/g, severity: 'high' },
            { name: 'document.write', pattern: /document\.write\s*\(/g, severity: 'high' },
            { name: 'document.writeln', pattern: /document\.writeln\s*\(/g, severity: 'high' },
            
            // jQuery
            { name: '$.html()', pattern: /\$\(.*\)\.html\s*\(/g, severity: 'high' },
            { name: '$.append()', pattern: /\$\(.*\)\.append\s*\(/g, severity: 'medium' },
            { name: '$.prepend()', pattern: /\$\(.*\)\.prepend\s*\(/g, severity: 'medium' },
            
            // Location
            { name: 'location', pattern: /location\s*=\s*/g, severity: 'medium' },
            { name: 'location.href', pattern: /location\.href\s*=/g, severity: 'medium' },
            { name: 'location.assign', pattern: /location\.assign\s*\(/g, severity: 'medium' },
            
            // Script injection
            { name: 'script.src', pattern: /\.src\s*=\s*(?!["'`]https?:\/\/)/g, severity: 'high' },
        ];

        // DOM sources (user-controllable inputs)
        this.domSources = [
            'location.hash',
            'location.search',
            'location.href',
            'document.URL',
            'document.documentURI',
            'document.referrer',
            'window.name',
            'document.cookie',
        ];

        // XSS test payloads for hash/fragment injection
        this.xssPayloads = [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<script>alert(1)</script>',
            '<iframe src="javascript:alert(1)">',
            '"-alert(1)-"',
            '\'-alert(1)-\'',
        ];

        // Framework-specific patterns
        this.frameworkPatterns = {
            react: {
                dangerous: /dangerouslySetInnerHTML/g,
                description: 'React dangerouslySetInnerHTML usage',
            },
            vue: {
                dangerous: /v-html\s*=/g,
                description: 'Vue v-html directive',
            },
            angular: {
                dangerous: /\[innerHTML\]\s*=/g,
                description: 'Angular innerHTML binding',
            },
        };
    }

    async run(ctx, inputs) {
        const { target, jsFiles = [] } = inputs;

        const results = {
            vulnerabilities: [],
            dangerous_sinks: [],
            tested_endpoints: 0,
        };

        this.setStatus('Analyzing for DOM XSS...');

        // Phase 1: Analyze JavaScript for dangerous sinks
        if (jsFiles.length > 0) {
            const sinks = await this.analyzeDangerousSinks(ctx, jsFiles, target);
            results.dangerous_sinks.push(...sinks);
        }

        // Phase 2: Test hash-based XSS
        const hashVulns = await this.testHashBasedXSS(ctx, target);
        results.vulnerabilities.push(...hashVulns);
        results.tested_endpoints += hashVulns.length;

        // Phase 3: Test URL parameter reflection in DOM
        const urlVulns = await this.testURLParameterXSS(ctx, target);
        results.vulnerabilities.push(...urlVulns);
        results.tested_endpoints += urlVulns.length;

        // Phase 4: Test postMessage vulnerabilities
        const pmVulns = await this.testPostMessageXSS(ctx, target);
        results.vulnerabilities.push(...pmVulns);

        this.setStatus(`Found ${results.vulnerabilities.length} DOM XSS vulnerabilities`);

        return results;
    }

    /**
     * Analyze JavaScript files for dangerous sinks
     */
    async analyzeDangerousSinks(ctx, jsFiles, target) {
        const sinks = [];

        for (const jsUrl of jsFiles.slice(0, 10)) { // Analyze first 10 JS files
            try {
                ctx.recordNetworkRequest();
                const response = await fetch(jsUrl, {
                    timeout: 10000,
                });

                if (!response.ok) continue;

                const jsCode = await response.text();

                // Check for dangerous sinks
                for (const sink of this.dangerousSinks) {
                    const matches = jsCode.match(sink.pattern);
                    
                    if (matches && matches.length > 0) {
                        // Check if sink uses DOM source
                        const usesSource = this.checkDOMSourceUsage(jsCode, sink.name);

                        const sinkData = {
                            sink: sink.name,
                            file: jsUrl,
                            occurrences: matches.length,
                            severity: sink.severity,
                            uses_dom_source: usesSource,
                        };

                        sinks.push(sinkData);

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dangerous_sink_found',
                            target,
                            payload: sinkData,
                        }));

                        // If sink uses DOM source, likely vulnerable
                        if (usesSource) {
                            ctx.emitClaim({
                                claim_type: 'unsafe_dom_manipulation',
                                subject: jsUrl,
                                predicate: { sink: sink.name, severity: sink.severity },
                                base_rate: 0.5,
                            });
                        }
                    }
                }

                // Check framework-specific patterns
                for (const [framework, pattern] of Object.entries(this.frameworkPatterns)) {
                    const matches = jsCode.match(pattern.dangerous);
                    
                    if (matches && matches.length > 0) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dangerous_sink_found',
                            target,
                            payload: {
                                framework,
                                pattern: pattern.description,
                                file: jsUrl,
                                occurrences: matches.length,
                            },
                        }));
                    }
                }

            } catch (error) {
                continue;
            }
        }

        return sinks;
    }

    /**
     * Check if code uses DOM sources with the sink
     */
    checkDOMSourceUsage(code, sinkName) {
        // Look for DOM sources near the sink
        const sinkIndex = code.indexOf(sinkName);
        if (sinkIndex === -1) return false;

        // Check 500 chars before and after
        const start = Math.max(0, sinkIndex - 500);
        const end = Math.min(code.length, sinkIndex + 500);
        const context = code.substring(start, end);

        // Check if any DOM source is referenced
        for (const source of this.domSources) {
            if (context.includes(source)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Test hash-based XSS (URL fragment)
     */
    async testHashBasedXSS(ctx, target) {
        const vulnerabilities = [];
        const baseUrl = target;

        for (const payload of this.xssPayloads.slice(0, 5)) {
            ctx.recordNetworkRequest();

            try {
                // Test with payload in hash
                const testUrl = `${baseUrl}#${encodeURIComponent(payload)}`;
                
                const response = await fetch(testUrl, {
                    method: 'GET',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                    },
                    timeout: 10000,
                });

                if (response.ok) {
                    const body = await response.text();
                    
                    // Check if payload is reflected in initial HTML
                    if (body.includes(payload)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dom_xss_detected',
                            target,
                            payload: {
                                type: 'hash_reflection',
                                payload,
                                url: testUrl,
                            },
                        }));

                        vulnerabilities.push({
                            type: 'dom_xss_hash',
                            url: baseUrl,
                            payload,
                            severity: 'medium',
                            confirmed: false, // Would need browser automation to confirm
                            description: 'Potential DOM XSS via URL hash/fragment',
                            impact: 'May allow XSS if hash value is processed by JavaScript',
                        });

                        break; // Found one, move on
                    }

                    // Check for JavaScript that processes location.hash
                    if (this.detectHashProcessing(body)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dom_xss_detected',
                            target,
                            payload: {
                                type: 'hash_processing',
                                url: baseUrl,
                            },
                        }));

                        vulnerabilities.push({
                            type: 'dom_xss_hash_processing',
                            url: baseUrl,
                            severity: 'medium',
                            confirmed: false,
                            description: 'JavaScript processes location.hash without sanitization',
                        });

                        break;
                    }
                }

            } catch (error) {
                continue;
            }
        }

        return vulnerabilities;
    }

    /**
     * Detect if page processes location.hash
     */
    detectHashProcessing(html) {
        // Look for inline scripts that use location.hash
        const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
        const scripts = html.match(scriptRegex) || [];

        for (const script of scripts) {
            if (script.includes('location.hash') || 
                script.includes('window.location.hash')) {
                
                // Check if it's used in a dangerous way
                if (script.includes('.innerHTML') || 
                    script.includes('.html(') ||
                    script.includes('eval') ||
                    script.includes('document.write')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Test URL parameter reflection in DOM
     */
    async testURLParameterXSS(ctx, target) {
        const vulnerabilities = [];
        const baseUrl = target;

        // Test common parameter names
        const testParams = ['q', 'search', 'query', 'name', 'message', 'callback'];

        for (const param of testParams) {
            ctx.recordNetworkRequest();

            try {
                const payload = '<img src=x onerror=alert(1)>';
                const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
                
                const response = await fetch(testUrl, {
                    method: 'GET',
                    timeout: 10000,
                });

                if (response.ok) {
                    const body = await response.text();
                    
                    // Check if parameter value appears in JavaScript context
                    if (this.detectJSContextReflection(body, payload, param)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dom_xss_confirmed',
                            target,
                            payload: {
                                type: 'url_parameter',
                                parameter: param,
                                payload,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'dom_xss_vulnerable',
                            subject: `${baseUrl}?${param}`,
                            predicate: { type: 'reflected_in_js', severity: 'high' },
                            base_rate: 0.5,
                        });

                        vulnerabilities.push({
                            type: 'dom_xss_reflected',
                            url: baseUrl,
                            parameter: param,
                            payload,
                            severity: 'high',
                            confirmed: true,
                            description: 'URL parameter reflected in JavaScript context',
                        });
                    }
                }

            } catch (error) {
                continue;
            }
        }

        return vulnerabilities;
    }

    /**
     * Detect reflection in JavaScript context
     */
    detectJSContextReflection(html, payload, param) {
        // Look for parameter value in <script> tags
        const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
        const scripts = html.match(scriptRegex) || [];

        for (const script of scripts) {
            // Check if payload appears in script
            if (script.includes(payload) || script.includes(param)) {
                return true;
            }

            // Check for patterns like: var x = location.search
            if (script.includes('location.search') || 
                script.includes('document.URL') ||
                script.includes('getParameter')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Test postMessage vulnerabilities
     */
    async testPostMessageXSS(ctx, target) {
        const vulnerabilities = [];

        try {
            ctx.recordNetworkRequest();
            const response = await fetch(target, {
                timeout: 10000,
            });

            if (response.ok) {
                const body = await response.text();
                
                // Check for postMessage event listeners
                if (body.includes('addEventListener') && 
                    (body.includes('message') || body.includes('postMessage'))) {
                    
                    // Check if message data is used unsafely
                    if (this.detectUnsafePostMessage(body)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'dom_xss_detected',
                            target,
                            payload: {
                                type: 'postMessage',
                                description: 'Unsafe postMessage handler',
                            },
                        }));

                        vulnerabilities.push({
                            type: 'dom_xss_postMessage',
                            url: target,
                            severity: 'medium',
                            confirmed: false,
                            description: 'postMessage event handler may be exploitable',
                            impact: 'Cross-origin scripts may inject content',
                        });
                    }
                }
            }

        } catch (error) {
            // Continue
        }

        return vulnerabilities;
    }

    /**
     * Detect unsafe postMessage usage
     */
    detectUnsafePostMessage(html) {
        const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
        const scripts = html.match(scriptRegex) || [];

        for (const script of scripts) {
            // Look for message event listener
            if (script.includes('addEventListener') && script.includes('message')) {
                // Check if event.data is used in dangerous sink
                if (script.includes('event.data') || script.includes('e.data')) {
                    if (script.includes('.innerHTML') || 
                        script.includes('eval') ||
                        script.includes('document.write')) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    normalizeBaseUrl(url) {
        try {
            const parsed = new URL(url);
            return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
        } catch {
            return url;
        }
    }
}

export default DOMXSSAgent;
