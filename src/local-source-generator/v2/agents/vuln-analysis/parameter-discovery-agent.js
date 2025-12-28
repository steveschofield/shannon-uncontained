/**
 * ParameterDiscoveryAgent - Parameter discovery and analysis agent
 * 
 * Discovers parameters from endpoints, detects hidden parameters via wordlists,
 * infers parameter types, and maps injection points for vulnerability testing.
 * 
 * CRITICAL FOR BLACKBOX MODE - Finds where to inject payloads without source code.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';

export class ParameterDiscoveryAgent extends BaseAgent {
    constructor(options = {}) {
        super('ParameterDiscoveryAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                discoveredEndpoints: {
                    type: 'array',
                    description: 'Previously discovered endpoints from crawler',
                    items: { type: 'object' }
                },
                use_arjun: { type: 'boolean', description: 'Use arjun for parameter discovery' },
                use_paramspider: { type: 'boolean', description: 'Use paramspider for parameter discovery' },
                arjun_max_urls: { type: 'number', description: 'Max URLs to scan with arjun' },
                paramspider_max_urls: { type: 'number', description: 'Max URLs to parse from paramspider results' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                parameters: { type: 'array', items: { type: 'object' } },
                injection_points: { type: 'array', items: { type: 'object' } },
                parameter_types: { type: 'object' },
                hidden_parameters: { type: 'array', items: { type: 'object' } },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'parameter_discovered',
                'parameter_type_inferred',
                'hidden_parameter_found',
                'injection_point_identified',
                'parameter_pollution_possible',
            ],
            model_updates: [],
            claims: [
                'parameter_exists',
                'parameter_reflected',
                'parameter_stored',
                'mass_assignment_possible',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 180000, // 3 minutes
            max_network_requests: 200,
            max_tokens: 0,
            max_tool_invocations: 4,
        };

        // Common parameter names to probe (lightweight wordlist)
        this.commonParams = [
            // ID parameters
            'id', 'uid', 'user_id', 'userId', 'productId', 'product_id',
            'item_id', 'itemId', 'order_id', 'orderId',
            
            // Search/filter
            'q', 'query', 'search', 'filter', 'sort', 'order',
            'keyword', 'term', 'name',
            
            // Pagination
            'page', 'limit', 'offset', 'per_page', 'perPage',
            'skip', 'take', 'count',
            
            // Common fields
            'email', 'username', 'password', 'token',
            'callback', 'redirect', 'url', 'return',
            'next', 'continue', 'dest', 'destination',
            
            // API specific
            'format', 'output', 'type', 'method',
            'action', 'cmd', 'command', 'exec',
            
            // Injection-prone
            'file', 'path', 'dir', 'folder',
            'template', 'view', 'include',
            'lang', 'locale', 'timezone',
            
            // Debug/admin
            'debug', 'test', 'dev', 'admin',
            'key', 'secret', 'api_key', 'apiKey',
        ];

        // Parameter type indicators
        this.typePatterns = {
            integer: /^\d+$/,
            float: /^\d+\.\d+$/,
            boolean: /^(true|false|1|0|yes|no)$/i,
            email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
            url: /^https?:\/\//i,
            base64: /^[A-Za-z0-9+/]+=*$/,
            jwt: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
        };
    }

    async run(ctx, inputs) {
        const {
            target,
            discoveredEndpoints = [],
            use_arjun: useArjunInput,
            use_paramspider: useParamspiderInput,
            arjun_max_urls: arjunMaxUrlsInput,
            paramspider_max_urls: paramspiderMaxUrlsInput,
        } = inputs;
        const baseUrl = this.normalizeBaseUrl(target);
        const toolConfig = inputs.toolConfig || ctx.config?.toolConfig || null;
        const useArjun = useArjunInput !== false;
        const useParamspider = useParamspiderInput !== false;
        const arjunMaxUrls = Number.isFinite(arjunMaxUrlsInput) ? Math.max(1, arjunMaxUrlsInput) : 10;
        const paramspiderMaxUrls = Number.isFinite(paramspiderMaxUrlsInput) ? Math.max(1, paramspiderMaxUrlsInput) : 50;
        const endpoints = this.resolveEndpoints(ctx, discoveredEndpoints, baseUrl);

        const results = {
            parameters: [],
            injection_points: [],
            parameter_types: {},
            hidden_parameters: [],
        };

        this.setStatus('Discovering parameters...');

        // Phase 1: Extract parameters from discovered endpoints
        if (endpoints.length > 0) {
            const extractedParams = await this.extractParametersFromEndpoints(
                ctx, 
                endpoints, 
                target
            );
            results.parameters.push(...extractedParams);
        }

        const toolParams = await this.discoverParametersWithTools(
            ctx,
            endpoints,
            baseUrl,
            target,
            { useArjun, useParamspider, arjunMaxUrls, paramspiderMaxUrls, toolConfig }
        );
        results.hidden_parameters.push(...toolParams);
        results.parameters.push(...toolParams);

        // Phase 2: Probe for hidden parameters
        const hiddenParams = await this.probeHiddenParameters(
            ctx,
            endpoints,
            baseUrl,
            target
        );
        results.hidden_parameters.push(...hiddenParams);
        results.parameters.push(...hiddenParams);

        // Phase 3: Infer parameter types
        const typeInferences = await this.inferParameterTypes(ctx, results.parameters, target);
        results.parameter_types = typeInferences;

        // Phase 4: Identify injection points
        const injectionPoints = await this.identifyInjectionPoints(
            ctx,
            results.parameters,
            target
        );
        results.injection_points.push(...injectionPoints);

        // Phase 5: Test for parameter pollution
        await this.testParameterPollution(ctx, discoveredEndpoints, target);

        this.setStatus(`Found ${results.parameters.length} parameters, ${results.injection_points.length} injection points`);

        return results;
    }

    /**
     * Extract parameters from discovered endpoints
     */
    async extractParametersFromEndpoints(ctx, endpoints, target) {
        const parameters = [];
        const seen = new Set();

        for (const endpoint of endpoints) {
            const url = endpoint.url || endpoint;
            
            try {
                const parsed = new URL(url);
                
                // Extract query parameters
                for (const [name, value] of parsed.searchParams.entries()) {
                    const key = `${parsed.pathname}:${name}`;
                    
                    if (!seen.has(key)) {
                        seen.add(key);
                        
                        const param = {
                            name,
                            value,
                            location: 'query',
                            endpoint: parsed.pathname,
                            url,
                            source: 'crawler',
                        };
                        
                        parameters.push(param);
                        
                        // Emit evidence
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'parameter_discovered',
                            target,
                            payload: {
                                parameter: name,
                                location: 'query',
                                endpoint: parsed.pathname,
                                example_value: value,
                            },
                        }));

                        // Emit claim
                        ctx.emitClaim({
                            claim_type: 'parameter_exists',
                            subject: `${parsed.pathname}?${name}`,
                            predicate: { location: 'query', type: 'unknown' },
                            base_rate: 0.5,
                        });
                    }
                }

                // Extract path parameters (e.g., /users/:id or /users/123)
                const pathParams = this.extractPathParameters(parsed.pathname);
                for (const pathParam of pathParams) {
                    const key = `${parsed.pathname}:${pathParam.name}`;
                    
                    if (!seen.has(key)) {
                        seen.add(key);
                        parameters.push({
                            ...pathParam,
                            endpoint: parsed.pathname,
                            url,
                            source: 'crawler',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'parameter_discovered',
                            target,
                            payload: {
                                parameter: pathParam.name,
                                location: 'path',
                                endpoint: parsed.pathname,
                            },
                        }));
                    }
                }

            } catch (error) {
                // Invalid URL, skip
                continue;
            }
        }

        return parameters;
    }

    /**
     * Extract path parameters from URL path
     */
    extractPathParameters(pathname) {
        const params = [];
        const segments = pathname.split('/').filter(Boolean);

        for (let i = 0; i < segments.length; i++) {
            const segment = segments[i];
            
            // Check if segment looks like an ID (numeric or UUID)
            if (/^\d+$/.test(segment)) {
                params.push({
                    name: `${segments[i - 1] || 'id'}_id`,
                    value: segment,
                    location: 'path',
                    position: i,
                    type: 'integer',
                });
            } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
                params.push({
                    name: `${segments[i - 1] || 'id'}_uuid`,
                    value: segment,
                    location: 'path',
                    position: i,
                    type: 'uuid',
                });
            }
        }

        return params;
    }

    /**
     * Probe for hidden parameters using wordlist
     */
    async probeHiddenParameters(ctx, endpoints, baseUrl, target) {
        const hidden = [];
        const testEndpoints = endpoints.slice(0, 5); // Test first 5 endpoints only

        for (const endpoint of testEndpoints) {
            const url = endpoint.url || endpoint;
            
            try {
                const parsed = new URL(url);
                const basePath = `${parsed.origin}${parsed.pathname}`;

                // Test common parameters
                for (const paramName of this.commonParams.slice(0, 20)) { // Test top 20 params
                    ctx.recordNetworkRequest();
                    
                    try {
                        // Test with benign value
                        const testUrl = `${basePath}?${paramName}=test`;
                        const response = await fetch(testUrl, {
                            method: 'GET',
                            headers: {
                                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                            },
                            timeout: 10000,
                        });

                        if (response.ok) {
                            const body = await response.text();
                            
                            // Check if parameter appears to be processed
                            if (this.parameterIsProcessed(body, paramName, 'test')) {
                                hidden.push({
                                    name: paramName,
                                    location: 'query',
                                    endpoint: parsed.pathname,
                                    url: testUrl,
                                    source: 'wordlist',
                                    evidence: 'parameter_reflected_or_processed',
                                });

                                ctx.emitEvidence(createEvidenceEvent({
                                    source: this.name,
                                    event_type: 'hidden_parameter_found',
                                    target,
                                    payload: {
                                        parameter: paramName,
                                        endpoint: parsed.pathname,
                                        method: 'wordlist_probe',
                                    },
                                }));

                                // Check if reflected (potential XSS)
                                if (body.includes('test')) {
                                    ctx.emitClaim({
                                        claim_type: 'parameter_reflected',
                                        subject: `${parsed.pathname}?${paramName}`,
                                        predicate: { location: 'query', reflected: true },
                                        base_rate: 0.5,
                                    });
                                }
                            }
                        }

                    } catch (error) {
                        // Timeout or network error, skip
                        continue;
                    }
                }

            } catch (error) {
                continue;
            }
        }

        return hidden;
    }

    /**
     * Check if parameter appears to be processed by the application
     */
    parameterIsProcessed(body, paramName, value) {
        // Check for reflection in response
        if (body.includes(value)) {
            return true;
        }

        // Check for parameter name in error messages
        const lowerBody = body.toLowerCase();
        if (lowerBody.includes(paramName.toLowerCase())) {
            return true;
        }

        // Check for JSON errors mentioning the parameter
        try {
            const json = JSON.parse(body);
            const jsonStr = JSON.stringify(json).toLowerCase();
            if (jsonStr.includes(paramName.toLowerCase())) {
                return true;
            }
        } catch (e) {
            // Not JSON
        }

        return false;
    }

    /**
     * Infer parameter types from values and names
     */
    async inferParameterTypes(ctx, parameters, target) {
        const types = {};

        for (const param of parameters) {
            const { name, value } = param;
            let inferredType = 'string'; // default

            // Try to infer from value
            if (value) {
                for (const [typeName, pattern] of Object.entries(this.typePatterns)) {
                    if (pattern.test(value)) {
                        inferredType = typeName;
                        break;
                    }
                }
            }

            // Try to infer from name
            if (inferredType === 'string') {
                const nameLower = name.toLowerCase();
                
                if (nameLower.includes('id') || nameLower.includes('count')) {
                    inferredType = 'integer';
                } else if (nameLower.includes('email')) {
                    inferredType = 'email';
                } else if (nameLower.includes('url') || nameLower.includes('redirect')) {
                    inferredType = 'url';
                } else if (nameLower.includes('token') || nameLower.includes('jwt')) {
                    inferredType = 'jwt';
                } else if (nameLower.includes('price') || nameLower.includes('amount')) {
                    inferredType = 'float';
                } else if (nameLower.includes('active') || nameLower.includes('enabled')) {
                    inferredType = 'boolean';
                }
            }

            types[name] = inferredType;

            // Emit evidence
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: 'parameter_type_inferred',
                target,
                payload: {
                    parameter: name,
                    type: inferredType,
                    confidence: value ? 'high' : 'medium',
                },
            }));
        }

        return types;
    }

    /**
     * Identify injection points based on parameter characteristics
     */
    async identifyInjectionPoints(ctx, parameters, target) {
        const injectionPoints = [];

        for (const param of parameters) {
            const { name, location, endpoint } = param;
            const nameLower = name.toLowerCase();

            const point = {
                parameter: name,
                location,
                endpoint,
                vulnerability_types: [],
            };

            // SQL Injection candidates
            if (nameLower.includes('id') || nameLower.includes('user') || 
                nameLower.includes('search') || nameLower.includes('query')) {
                point.vulnerability_types.push('sql_injection');
            }

            // NoSQL Injection candidates
            if (location === 'query' && (nameLower.includes('id') || 
                nameLower.includes('filter') || nameLower.includes('where'))) {
                point.vulnerability_types.push('nosql_injection');
            }

            // XSS candidates (reflected parameters)
            if (location === 'query' && (nameLower.includes('search') || 
                nameLower.includes('query') || nameLower.includes('name') ||
                nameLower.includes('message'))) {
                point.vulnerability_types.push('xss');
            }

            // Command Injection candidates
            if (nameLower.includes('file') || nameLower.includes('path') ||
                nameLower.includes('cmd') || nameLower.includes('exec') ||
                nameLower.includes('command')) {
                point.vulnerability_types.push('command_injection');
            }

            // SSRF candidates
            if (nameLower.includes('url') || nameLower.includes('redirect') ||
                nameLower.includes('callback') || nameLower.includes('webhook') ||
                nameLower.includes('fetch')) {
                point.vulnerability_types.push('ssrf');
            }

            // Path Traversal candidates
            if (nameLower.includes('file') || nameLower.includes('path') ||
                nameLower.includes('dir') || nameLower.includes('folder') ||
                nameLower.includes('include')) {
                point.vulnerability_types.push('path_traversal');
            }

            // Template Injection candidates
            if (nameLower.includes('template') || nameLower.includes('view') ||
                nameLower.includes('render')) {
                point.vulnerability_types.push('template_injection');
            }

            // Only emit if we identified potential vulnerabilities
            if (point.vulnerability_types.length > 0) {
                injectionPoints.push(point);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'injection_point_identified',
                    target,
                    payload: {
                        parameter: name,
                        location,
                        endpoint,
                        potential_vulnerabilities: point.vulnerability_types,
                    },
                }));
            }
        }

        return injectionPoints;
    }

    /**
     * Test for parameter pollution vulnerabilities
     */
    async testParameterPollution(ctx, endpoints, target) {
        const testEndpoints = endpoints.slice(0, 3); // Test first 3 only

        for (const endpoint of testEndpoints) {
            const url = endpoint.url || endpoint;

            try {
                const parsed = new URL(url);
                
                // Test duplicate parameter handling
                if (parsed.searchParams.size > 0) {
                    const firstParam = Array.from(parsed.searchParams.keys())[0];
                    const testUrl = `${parsed.origin}${parsed.pathname}?${firstParam}=value1&${firstParam}=value2`;

                    ctx.recordNetworkRequest();
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        timeout: 10000,
                    });

                    if (response.ok) {
                        const body = await response.text();
                        
                        // Check which value was used
                        if (body.includes('value1') || body.includes('value2')) {
                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: 'parameter_pollution_possible',
                                target,
                                payload: {
                                    endpoint: parsed.pathname,
                                    parameter: firstParam,
                                    behavior: 'accepts_duplicate_parameters',
                                },
                            }));
                        }
                    }
                }

            } catch (error) {
                continue;
            }
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================
    resolveEndpoints(ctx, discoveredEndpoints, baseUrl) {
        const endpoints = new Set();

        for (const endpoint of discoveredEndpoints || []) {
            if (!endpoint) continue;
            const url = endpoint.url || endpoint;
            if (typeof url === 'string') {
                endpoints.add(url);
            }
        }

        if (endpoints.size === 0) {
            const events = ctx.evidenceGraph.getEventsByType(EVENT_TYPES.ENDPOINT_DISCOVERED) || [];
            for (const event of events) {
                const payload = event.payload || {};
                if (payload.url) {
                    endpoints.add(payload.url);
                } else if (payload.path) {
                    try {
                        endpoints.add(new URL(payload.path, baseUrl).toString());
                    } catch {}
                }
            }
        }

        return Array.from(endpoints);
    }

    async discoverParametersWithTools(ctx, endpoints, baseUrl, target, options) {
        const {
            useArjun,
            useParamspider,
            arjunMaxUrls,
            paramspiderMaxUrls,
            toolConfig,
        } = options || {};
        const results = [];
        const seen = new Set();

        if (useArjun && await isToolAvailable('arjun')) {
            const arjunTargets = endpoints.slice(0, arjunMaxUrls);
            for (const url of arjunTargets) {
                const params = await this.runArjun(ctx, url, target, toolConfig);
                for (const param of params) {
                    const key = `${param.endpoint}:${param.name}`;
                    if (seen.has(key)) continue;
                    seen.add(key);
                    results.push(param);
                }
            }
        }

        if (useParamspider && await isToolAvailable('paramspider')) {
            const domain = this.safeHostname(baseUrl);
            if (domain) {
                const params = await this.runParamspider(ctx, domain, target, paramspiderMaxUrls, toolConfig);
                for (const param of params) {
                    const key = `${param.endpoint}:${param.name}`;
                    if (seen.has(key)) continue;
                    seen.add(key);
                    results.push(param);
                }
            }
        }

        return results;
    }

    async runArjun(ctx, url, target, toolConfig) {
        ctx.recordToolInvocation();
        const toolOptions = getToolRunOptions('arjun', toolConfig);
        const cmd = `arjun -u "${url}"`;
        const result = await runToolWithRetry(cmd, {
            ...toolOptions,
            context: ctx,
        });

        if (!result.success) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                target,
                payload: { tool: 'arjun', error: result.error, url },
            }));
            return [];
        }

        const params = this.parseArjunOutput(result.stdout);
        return params.map(name => this.emitDiscoveredParameter(ctx, {
            name,
            location: 'query',
            endpoint: this.pathFromUrl(url),
            url,
            source: 'arjun',
        }, target));
    }

    parseArjunOutput(stdout) {
        const params = new Set();
        const trimmed = String(stdout || '').trim();
        if (!trimmed) return [];

        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                const data = JSON.parse(trimmed);
                const list = data.parameters || data.params || data;
                if (Array.isArray(list)) {
                    for (const item of list) {
                        if (typeof item === 'string') params.add(item);
                    }
                }
            } catch {}
        }

        const lines = trimmed.split('\n');
        for (const line of lines) {
            const match = line.match(/parameters?\s+found\s*:\s*(.+)$/i);
            if (match) {
                match[1].split(/[, ]+/).forEach(p => params.add(p.trim()));
            }
        }

        return Array.from(params).filter(Boolean);
    }

    async runParamspider(ctx, domain, target, maxUrls, toolConfig) {
        ctx.recordToolInvocation();
        const { fs, path } = await import('zx');
        const tmpDir = await fs.mkdtemp(path.join(process.cwd(), 'tmp-paramspider-'));
        const toolOptions = getToolRunOptions('paramspider', toolConfig);
        const cmd = `paramspider -d ${domain}`;
        const result = await runToolWithRetry(cmd, {
            ...toolOptions,
            context: ctx,
            cwd: tmpDir,
        });

        if (!result.success) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                target,
                payload: { tool: 'paramspider', error: result.error, domain },
            }));
            return [];
        }

        const outputFile = path.join(tmpDir, 'results', `${domain}.txt`);
        const content = await this.readIfExists(fs, outputFile, result.stdout);
        const params = [];
        const lines = String(content || '').split('\n').map(l => l.trim()).filter(Boolean);
        for (const line of lines.slice(0, maxUrls)) {
            try {
                const parsed = new URL(line);
                for (const [name, value] of parsed.searchParams.entries()) {
                    params.push(this.emitDiscoveredParameter(ctx, {
                        name,
                        value,
                        location: 'query',
                        endpoint: parsed.pathname,
                        url: parsed.toString(),
                        source: 'paramspider',
                    }, target));
                }
            } catch {}
        }

        return params;
    }

    emitDiscoveredParameter(ctx, param, target) {
        ctx.emitEvidence(createEvidenceEvent({
            source: this.name,
            event_type: 'parameter_discovered',
            target,
            payload: {
                parameter: param.name,
                location: param.location,
                endpoint: param.endpoint,
                example_value: param.value,
                source: param.source,
            },
        }));

        return param;
    }

    async readIfExists(fs, filePath, fallback = '') {
        try {
            if (await fs.pathExists(filePath)) {
                return await fs.readFile(filePath, 'utf-8');
            }
        } catch {}
        return fallback || '';
    }

    pathFromUrl(url) {
        try {
            return new URL(url).pathname;
        } catch {
            return url;
        }
    }

    safeHostname(baseUrl) {
        if (!baseUrl) return null;
        try {
            return new URL(baseUrl).hostname;
        } catch {
            return baseUrl.replace(/^https?:\/\//, '').split('/')[0];
        }
    }

    normalizeBaseUrl(url) {
        try {
            const parsed = new URL(url);
            return `${parsed.protocol}//${parsed.host}`;
        } catch {
            return url;
        }
    }
}

export default ParameterDiscoveryAgent;
