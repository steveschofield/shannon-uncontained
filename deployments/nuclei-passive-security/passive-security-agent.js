/**
 * PassiveSecurityAgent - Passive security analysis agent
 * 
 * Analyzes HTTP responses already collected by other agents (crawler, recon, etc.)
 * WITHOUT sending any new requests. Looks for information leakage, debug data,
 * secrets, and security issues in responses.
 * 
 * What it finds:
 * - API keys, tokens, credentials in JavaScript
 * - Commented-out code with sensitive data
 * - Stack traces and error messages
 * - Debug flags and developer comments
 * - Version numbers and technology disclosure
 * - Email addresses and internal IPs
 * - TODO/FIXME comments revealing issues
 * - Backup files and source maps
 * 
 * Think of it as: "Forensic analysis of what the server already told us"
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';

export class PassiveSecurityAgent extends BaseAgent {
    constructor(options = {}) {
        super('PassiveSecurityAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['responses'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                responses: {
                    type: 'array',
                    description: 'HTTP responses from crawler/recon agents',
                    items: { 
                        type: 'object',
                        properties: {
                            url: { type: 'string' },
                            status: { type: 'number' },
                            headers: { type: 'object' },
                            body: { type: 'string' },
                        }
                    }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                information_leaks: { type: 'array', items: { type: 'object' } },
                debug_findings: { type: 'array', items: { type: 'object' } },
                secrets_found: { type: 'array', items: { type: 'object' } },
                technology_disclosure: { type: 'array', items: { type: 'object' } },
                total_findings: { type: 'number' },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED, 'http_response'],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'information_disclosure',
                'secret_exposed',
                'debug_mode_detected',
                'technology_disclosed',
                'sensitive_comment_found',
            ],
            model_updates: [],
            claims: [
                'information_leak',
                'debug_enabled',
                'source_code_exposed',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 120000, // 2 minutes
            max_network_requests: 0, // Passive - no requests
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Secret patterns (regex)
        this.secretPatterns = [
            // AWS
            { 
                name: 'AWS Access Key', 
                pattern: /AKIA[0-9A-Z]{16}/g,
                severity: 'critical',
            },
            {
                name: 'AWS Secret Key',
                pattern: /aws_secret_access_key\s*=\s*["']([a-zA-Z0-9/+=]{40})["']/gi,
                severity: 'critical',
            },
            
            // API Keys
            {
                name: 'Generic API Key',
                pattern: /api[_-]?key\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
                severity: 'high',
            },
            {
                name: 'Authorization Token',
                pattern: /(?:token|auth|bearer)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{20,})["']/gi,
                severity: 'high',
            },
            
            // Google
            {
                name: 'Google API Key',
                pattern: /AIza[0-9A-Za-z_\-]{35}/g,
                severity: 'high',
            },
            
            // GitHub
            {
                name: 'GitHub Token',
                pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
                severity: 'critical',
            },
            
            // Slack
            {
                name: 'Slack Token',
                pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g,
                severity: 'high',
            },
            
            // Database URLs
            {
                name: 'Database Connection String',
                pattern: /(?:mongodb|mysql|postgresql|postgres):\/\/[^\s"'<>]+/gi,
                severity: 'critical',
            },
            
            // Private Keys
            {
                name: 'Private Key',
                pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
                severity: 'critical',
            },
            
            // Passwords in code
            {
                name: 'Hardcoded Password',
                pattern: /password\s*[:=]\s*["']([^"']{6,})["']/gi,
                severity: 'high',
            },
            
            // JWT
            {
                name: 'JWT Token',
                pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
                severity: 'medium',
            },
        ];

        // Debug patterns
        this.debugPatterns = [
            {
                name: 'Debug Mode Enabled',
                pattern: /(?:debug|DEBUG)\s*[:=]\s*(?:true|1|on|enabled)/gi,
                severity: 'medium',
            },
            {
                name: 'Development Environment',
                pattern: /(?:environment|env)\s*[:=]\s*["'](?:dev|development|local)["']/gi,
                severity: 'low',
            },
            {
                name: 'Stack Trace',
                pattern: /(?:at\s+[a-zA-Z0-9_$]+\s*\([^)]+:\d+:\d+\)|Traceback|Exception in thread)/g,
                severity: 'medium',
            },
            {
                name: 'SQL Error',
                pattern: /(?:SQL syntax|mysql_|pg_query|ORA-\d{5}|SQLite)/gi,
                severity: 'medium',
            },
        ];

        // Technology disclosure patterns
        this.techPatterns = [
            {
                name: 'Framework Version',
                pattern: /(?:react|angular|vue|django|rails|laravel|express)[\s\/]*([\d.]+)/gi,
                severity: 'low',
            },
            {
                name: 'Server Software',
                pattern: /(?:apache|nginx|iis)[\s\/]*([\d.]+)/gi,
                severity: 'low',
            },
            {
                name: 'PHP Version',
                pattern: /php[\s\/]*([\d.]+)/gi,
                severity: 'low',
            },
        ];

        // Comment patterns
        this.commentPatterns = [
            {
                name: 'TODO Comment',
                pattern: /(?:\/\/|\/\*|<!--)\s*TODO:?\s*([^\n\r*]+)/gi,
                severity: 'info',
            },
            {
                name: 'FIXME Comment',
                pattern: /(?:\/\/|\/\*|<!--)\s*FIXME:?\s*([^\n\r*]+)/gi,
                severity: 'info',
            },
            {
                name: 'XXX Comment',
                pattern: /(?:\/\/|\/\*|<!--)\s*XXX:?\s*([^\n\r*]+)/gi,
                severity: 'info',
            },
            {
                name: 'HACK Comment',
                pattern: /(?:\/\/|\/\*|<!--)\s*HACK:?\s*([^\n\r*]+)/gi,
                severity: 'low',
            },
            {
                name: 'BUG Comment',
                pattern: /(?:\/\/|\/\*|<!--)\s*BUG:?\s*([^\n\r*]+)/gi,
                severity: 'low',
            },
        ];

        // Email and IP patterns
        this.piiPatterns = [
            {
                name: 'Email Address',
                pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
                severity: 'info',
            },
            {
                name: 'Internal IP Address',
                pattern: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,
                severity: 'low',
            },
        ];
    }

    async run(ctx, inputs) {
        const { target, responses = [] } = inputs;

        const results = {
            information_leaks: [],
            debug_findings: [],
            secrets_found: [],
            technology_disclosure: [],
            total_findings: 0,
        };

        if (responses.length === 0) {
            this.setStatus('No responses to analyze');
            return results;
        }

        this.setStatus(`Analyzing ${responses.length} responses...`);

        // Analyze each response
        for (const response of responses) {
            await this.analyzeResponse(ctx, response, results, target);
        }

        results.total_findings = 
            results.information_leaks.length +
            results.debug_findings.length +
            results.secrets_found.length +
            results.technology_disclosure.length;

        this.setStatus(`Found ${results.total_findings} passive security issues`);

        return results;
    }

    /**
     * Analyze a single response
     */
    async analyzeResponse(ctx, response, results, target) {
        const { url, body, headers = {} } = response;

        if (!body) return;

        // 1. Check for secrets
        this.findSecrets(ctx, url, body, results, target);

        // 2. Check for debug info
        this.findDebugInfo(ctx, url, body, results, target);

        // 3. Check for technology disclosure
        this.findTechDisclosure(ctx, url, body, headers, results, target);

        // 4. Check for comments
        this.findComments(ctx, url, body, results, target);

        // 5. Check for PII
        this.findPII(ctx, url, body, results, target);

        // 6. Check for source maps
        this.checkSourceMaps(ctx, url, body, results, target);

        // 7. Check for backup files
        this.checkBackupFiles(ctx, url, results, target);
    }

    /**
     * Find secrets in response
     */
    findSecrets(ctx, url, body, results, target) {
        for (const { name, pattern, severity } of this.secretPatterns) {
            const matches = body.match(pattern);
            
            if (matches && matches.length > 0) {
                // Deduplicate
                const uniqueMatches = [...new Set(matches)];
                
                for (const match of uniqueMatches) {
                    const finding = {
                        type: 'secret',
                        name,
                        severity,
                        url,
                        value: this.maskSecret(match),
                        context: this.getContext(body, match),
                    };

                    results.secrets_found.push(finding);

                    // Emit evidence for high/critical secrets
                    if (severity === 'critical' || severity === 'high') {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'secret_exposed',
                            target,
                            payload: {
                                secret_type: name,
                                severity,
                                url,
                                masked_value: finding.value,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'information_leak',
                            subject: url,
                            predicate: { 
                                type: 'secret',
                                severity,
                                secret_type: name,
                            },
                            base_rate: 0.5,
                        });
                    }
                }
            }
        }
    }

    /**
     * Find debug information
     */
    findDebugInfo(ctx, url, body, results, target) {
        for (const { name, pattern, severity } of this.debugPatterns) {
            const matches = body.match(pattern);
            
            if (matches && matches.length > 0) {
                const finding = {
                    type: 'debug',
                    name,
                    severity,
                    url,
                    occurrences: matches.length,
                    sample: matches[0],
                };

                results.debug_findings.push(finding);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'debug_mode_detected',
                    target,
                    payload: {
                        debug_type: name,
                        severity,
                        url,
                        occurrences: matches.length,
                    },
                }));

                if (name === 'Debug Mode Enabled') {
                    ctx.emitClaim({
                        claim_type: 'debug_enabled',
                        subject: url,
                        predicate: { severity },
                        base_rate: 0.5,
                    });
                }
            }
        }
    }

    /**
     * Find technology disclosure
     */
    findTechDisclosure(ctx, url, body, headers, results, target) {
        // Check body
        for (const { name, pattern, severity } of this.techPatterns) {
            const matches = body.match(pattern);
            
            if (matches && matches.length > 0) {
                const finding = {
                    type: 'technology',
                    name,
                    severity,
                    url,
                    versions: [...new Set(matches)],
                };

                results.technology_disclosure.push(finding);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'technology_disclosed',
                    target,
                    payload: {
                        technology: name,
                        versions: finding.versions,
                        url,
                    },
                }));
            }
        }

        // Check headers
        const techHeaders = ['x-powered-by', 'server', 'x-aspnet-version'];
        for (const header of techHeaders) {
            const value = headers[header] || headers[header.toLowerCase()];
            if (value) {
                const finding = {
                    type: 'technology',
                    name: 'Server Header',
                    severity: 'low',
                    url,
                    value,
                };

                results.technology_disclosure.push(finding);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'technology_disclosed',
                    target,
                    payload: {
                        technology: header,
                        value,
                        url,
                    },
                }));
            }
        }
    }

    /**
     * Find interesting comments
     */
    findComments(ctx, url, body, results, target) {
        for (const { name, pattern, severity } of this.commentPatterns) {
            const matches = [...body.matchAll(pattern)];
            
            if (matches.length > 0) {
                for (const match of matches.slice(0, 5)) { // Limit to 5 per type
                    const finding = {
                        type: 'comment',
                        name,
                        severity,
                        url,
                        content: match[1] ? match[1].trim() : match[0],
                    };

                    results.information_leaks.push(finding);

                    if (severity !== 'info') {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'sensitive_comment_found',
                            target,
                            payload: {
                                comment_type: name,
                                severity,
                                url,
                                content: finding.content.substring(0, 100),
                            },
                        }));
                    }
                }
            }
        }
    }

    /**
     * Find PII (emails, internal IPs)
     */
    findPII(ctx, url, body, results, target) {
        for (const { name, pattern, severity } of this.piiPatterns) {
            const matches = body.match(pattern);
            
            if (matches && matches.length > 0) {
                const uniqueMatches = [...new Set(matches)].slice(0, 10); // Limit to 10
                
                const finding = {
                    type: 'pii',
                    name,
                    severity,
                    url,
                    count: matches.length,
                    samples: uniqueMatches,
                };

                results.information_leaks.push(finding);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'information_disclosure',
                    target,
                    payload: {
                        disclosure_type: name,
                        severity,
                        url,
                        count: matches.length,
                    },
                }));
            }
        }
    }

    /**
     * Check for source maps
     */
    checkSourceMaps(ctx, url, body, results, target) {
        const sourceMapPattern = /\/\/[@#]\s*sourceMappingURL=([^\s]+)/g;
        const matches = body.match(sourceMapPattern);
        
        if (matches && matches.length > 0) {
            const finding = {
                type: 'source_map',
                name: 'Source Map Exposed',
                severity: 'medium',
                url,
                maps: matches,
            };

            results.information_leaks.push(finding);

            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: 'information_disclosure',
                target,
                payload: {
                    disclosure_type: 'source_map',
                    severity: 'medium',
                    url,
                    count: matches.length,
                },
            }));

            ctx.emitClaim({
                claim_type: 'source_code_exposed',
                subject: url,
                predicate: { type: 'source_map' },
                base_rate: 0.5,
            });
        }
    }

    /**
     * Check for backup files in URL
     */
    checkBackupFiles(ctx, url, results, target) {
        const backupPatterns = [
            /\.bak$/i,
            /\.backup$/i,
            /\.old$/i,
            /\.copy$/i,
            /~$/,
            /\.swp$/i,
        ];

        for (const pattern of backupPatterns) {
            if (pattern.test(url)) {
                const finding = {
                    type: 'backup_file',
                    name: 'Backup File Accessible',
                    severity: 'high',
                    url,
                };

                results.information_leaks.push(finding);

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'information_disclosure',
                    target,
                    payload: {
                        disclosure_type: 'backup_file',
                        severity: 'high',
                        url,
                    },
                }));

                break; // One finding per URL is enough
            }
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * Mask secret for safe logging
     */
    maskSecret(secret) {
        if (secret.length <= 8) {
            return '***';
        }
        const visible = Math.min(4, Math.floor(secret.length / 4));
        return secret.substring(0, visible) + '***' + secret.substring(secret.length - visible);
    }

    /**
     * Get context around a match
     */
    getContext(body, match, contextSize = 100) {
        const index = body.indexOf(match);
        if (index === -1) return '';
        
        const start = Math.max(0, index - contextSize);
        const end = Math.min(body.length, index + match.length + contextSize);
        
        return '...' + body.substring(start, end) + '...';
    }
}

export default PassiveSecurityAgent;
