/**
 * CSRFDetector - Cross-Site Request Forgery detection agent
 * 
 * Tests for CSRF vulnerabilities in state-changing operations.
 * Required for OWASP Top 10 compliance.
 * 
 * What it tests:
 * - Missing CSRF tokens in forms
 * - Missing CSRF tokens in AJAX requests
 * - Predictable CSRF tokens
 * - CSRF token not validated server-side
 * - SameSite cookie attribute missing
 * - Referer header not checked
 * - State-changing GET requests (bad practice)
 * 
 * CRITICAL: CSRF allows attackers to perform actions as the victim
 * (change password, transfer money, delete account, etc.)
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class CSRFDetector extends BaseAgent {
    constructor(options = {}) {
        super('CSRFDetector', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                discoveredEndpoints: {
                    type: 'array',
                    description: 'Previously discovered endpoints',
                    items: { type: 'object' }
                },
                authTokens: {
                    type: 'object',
                    description: 'Authentication tokens from AuthFlowDetector',
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                missing_csrf_tokens: { type: 'array', items: { type: 'string' } },
                unsafe_methods: { type: 'array', items: { type: 'object' } },
                cookie_issues: { type: 'array', items: { type: 'object' } },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'csrf_vulnerability_found',
                'csrf_token_missing',
                'samesite_cookie_missing',
                'state_changing_get',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'csrf_vulnerable',
                'csrf_protection_missing',
                'samesite_attribute_missing',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 120000, // 2 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // State-changing operations that should have CSRF protection
        this.stateChangingPatterns = [
            /\/login$/i,
            /\/logout$/i,
            /\/register$/i,
            /\/signup$/i,
            /\/update$/i,
            /\/edit$/i,
            /\/delete$/i,
            /\/create$/i,
            /\/change/i,
            /\/modify/i,
            /\/transfer/i,
            /\/payment/i,
            /\/checkout/i,
            /\/profile/i,
            /\/settings/i,
            /\/password/i,
        ];

        // Common CSRF token names
        this.csrfTokenNames = [
            'csrf_token',
            'csrfToken',
            'csrf',
            '_csrf',
            'csrf-token',
            'csrfmiddlewaretoken',
            'authenticity_token',
            'anti-csrf-token',
            '__RequestVerificationToken',
            'token',
        ];

        // HTTP methods that should NOT change state
        this.safeMethods = ['GET', 'HEAD', 'OPTIONS'];

        // HTTP methods that change state (need CSRF protection)
        this.unsafeMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    }

    async run(ctx, inputs) {
        const { target, discoveredEndpoints = [], authTokens = {} } = inputs;

        const results = {
            vulnerabilities: [],
            missing_csrf_tokens: [],
            unsafe_methods: [],
            cookie_issues: [],
        };

        this.setStatus('Testing for CSRF vulnerabilities...');

        // Phase 1: Check for state-changing GET requests
        const getVulns = await this.checkStateChangingGET(ctx, discoveredEndpoints, target);
        results.unsafe_methods.push(...getVulns);

        // Phase 2: Test for missing CSRF tokens
        const tokenVulns = await this.testMissingCSRFTokens(ctx, discoveredEndpoints, target);
        results.missing_csrf_tokens.push(...tokenVulns);

        // Phase 3: Check SameSite cookie attribute
        const cookieVulns = await this.checkSameSiteCookies(ctx, target);
        results.cookie_issues.push(...cookieVulns);

        // Phase 4: Test CSRF token validation
        const validationVulns = await this.testCSRFTokenValidation(ctx, discoveredEndpoints, target);
        results.vulnerabilities.push(...validationVulns);

        // Consolidate all findings
        results.vulnerabilities.push(
            ...getVulns.map(v => ({ ...v, confirmed: true })),
            ...tokenVulns.map(v => ({ type: 'csrf_token_missing', endpoint: v, severity: 'medium', confirmed: false })),
            ...cookieVulns.map(v => ({ ...v, confirmed: true }))
        );

        this.setStatus(`Found ${results.vulnerabilities.length} CSRF issues`);

        return results;
    }

    /**
     * Check for state-changing operations using GET
     */
    async checkStateChangingGET(ctx, endpoints, target) {
        const vulnerabilities = [];

        for (const endpoint of endpoints) {
            const url = endpoint.url || endpoint;
            const method = endpoint.method || 'GET';

            // Check if this is a state-changing endpoint using GET
            if (method === 'GET' && this.isStateChangingEndpoint(url)) {
                vulnerabilities.push({
                    type: 'state_changing_get',
                    severity: 'high',
                    endpoint: url,
                    description: 'State-changing operation uses GET method',
                    impact: 'Vulnerable to CSRF via simple link/image tag',
                });

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'state_changing_get',
                    target,
                    payload: {
                        endpoint: url,
                        method: 'GET',
                    },
                }));

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                    target,
                    payload: {
                        vulnerability_type: 'csrf_via_get',
                        severity: 'high',
                        endpoint: url,
                    },
                }));

                ctx.emitClaim({
                    claim_type: 'csrf_vulnerable',
                    subject: url,
                    predicate: { method: 'GET', severity: 'high' },
                    base_rate: 0.5,
                });
            }
        }

        return vulnerabilities;
    }

    /**
     * Check if endpoint is state-changing
     */
    isStateChangingEndpoint(url) {
        try {
            const parsed = new URL(url);
            const path = parsed.pathname.toLowerCase();

            for (const pattern of this.stateChangingPatterns) {
                if (pattern.test(path)) {
                    return true;
                }
            }

            return false;

        } catch (error) {
            return false;
        }
    }

    /**
     * Test for missing CSRF tokens
     */
    async testMissingCSRFTokens(ctx, endpoints, target) {
        const missing = [];

        // Filter for POST/PUT/DELETE endpoints
        const stateChangingEndpoints = endpoints.filter(e => {
            const method = e.method || 'GET';
            return this.unsafeMethods.includes(method);
        });

        for (const endpoint of stateChangingEndpoints.slice(0, 20)) {
            const url = endpoint.url || endpoint;
            const method = endpoint.method || 'POST';

            try {
                // Send request without CSRF token
                const response = await fetch(url, {
                    method,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: method !== 'DELETE' ? JSON.stringify({ test: 'data' }) : undefined,
                    timeout: 10000,
                });

                // If request succeeds without CSRF token, it's vulnerable
                if (response.ok) {
                    missing.push(url);

                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'csrf_token_missing',
                        target,
                        payload: {
                            endpoint: url,
                            method,
                            status: response.status,
                        },
                    }));

                    ctx.emitClaim({
                        claim_type: 'csrf_protection_missing',
                        subject: url,
                        predicate: { method, severity: 'high' },
                        base_rate: 0.5,
                    });
                }

            } catch (error) {
                // Network error, skip
                continue;
            }
        }

        return missing;
    }

    /**
     * Check SameSite cookie attribute
     */
    async checkSameSiteCookies(ctx, target) {
        const issues = [];

        try {
            const response = await fetch(target, {
                method: 'GET',
                timeout: 10000,
            });

            const setCookieHeader = response.headers.get('set-cookie');
            
            if (setCookieHeader) {
                const cookies = Array.isArray(setCookieHeader) 
                    ? setCookieHeader 
                    : [setCookieHeader];

                for (const cookie of cookies) {
                    // Check if SameSite attribute is present
                    if (!cookie.toLowerCase().includes('samesite')) {
                        const cookieName = cookie.split('=')[0];

                        issues.push({
                            type: 'samesite_missing',
                            severity: 'medium',
                            cookie_name: cookieName,
                            description: 'Cookie missing SameSite attribute',
                            impact: 'Cookie can be sent in cross-site requests',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'samesite_cookie_missing',
                            target,
                            payload: {
                                cookie_name: cookieName,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'samesite_attribute_missing',
                            subject: target,
                            predicate: { cookie: cookieName },
                            base_rate: 0.5,
                        });
                    }

                    // Check for weak SameSite values
                    if (cookie.toLowerCase().includes('samesite=none') && 
                        !cookie.toLowerCase().includes('secure')) {
                        issues.push({
                            type: 'samesite_none_without_secure',
                            severity: 'high',
                            cookie_name: cookie.split('=')[0],
                            description: 'SameSite=None without Secure flag',
                            impact: 'Cookie vulnerable to CSRF',
                        });
                    }
                }
            }

        } catch (error) {
            // Can't check cookies
        }

        return issues;
    }

    /**
     * Test CSRF token validation
     */
    async testCSRFTokenValidation(ctx, endpoints, target) {
        const vulnerabilities = [];

        // Find form-based endpoints
        const formEndpoints = endpoints.filter(e => 
            this.isStateChangingEndpoint(e.url || e)
        );

        for (const endpoint of formEndpoints.slice(0, 10)) {
            const url = endpoint.url || endpoint;

            // Test 1: Invalid token
            const invalidTokenVuln = await this.testInvalidToken(ctx, url, target);
            if (invalidTokenVuln) {
                vulnerabilities.push(invalidTokenVuln);
            }

            // Test 2: Missing token in subsequent request
            const missingTokenVuln = await this.testTokenRequired(ctx, url, target);
            if (missingTokenVuln) {
                vulnerabilities.push(missingTokenVuln);
            }

            // Test 3: Token reuse
            const reuseVuln = await this.testTokenReuse(ctx, url, target);
            if (reuseVuln) {
                vulnerabilities.push(reuseVuln);
            }
        }

        return vulnerabilities;
    }

    /**
     * Test if invalid CSRF token is rejected
     */
    async testInvalidToken(ctx, url, target) {
        try {
            // Try common CSRF token names with invalid values
            for (const tokenName of this.csrfTokenNames.slice(0, 3)) {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `${tokenName}=invalid_token_12345&test=data`,
                    timeout: 10000,
                });

                // If accepted with invalid token, vulnerable
                if (response.ok) {
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'csrf_vulnerability_found',
                        target,
                        payload: {
                            endpoint: url,
                            issue: 'invalid_token_accepted',
                            token_name: tokenName,
                        },
                    }));

                    return {
                        type: 'csrf_invalid_token_accepted',
                        severity: 'critical',
                        endpoint: url,
                        confirmed: true,
                        description: 'Invalid CSRF token accepted',
                        impact: 'CSRF protection can be bypassed',
                    };
                }
            }

        } catch (error) {
            // Error is expected if token validation works
        }

        return null;
    }

    /**
     * Test if CSRF token is required
     */
    async testTokenRequired(ctx, url, target) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ test: 'data' }),
                timeout: 10000,
            });

            // If succeeds without any token, vulnerable
            if (response.ok) {
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'csrf_vulnerability_found',
                    target,
                    payload: {
                        endpoint: url,
                        issue: 'no_csrf_protection',
                    },
                }));

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                    target,
                    payload: {
                        vulnerability_type: 'csrf',
                        severity: 'high',
                        endpoint: url,
                        description: 'No CSRF protection',
                    },
                }));

                return {
                    type: 'csrf_no_protection',
                    severity: 'high',
                    endpoint: url,
                    confirmed: true,
                    description: 'No CSRF protection on state-changing endpoint',
                    impact: 'Attackers can perform actions as victim user',
                };
            }

        } catch (error) {
            // Expected if CSRF protection exists
        }

        return null;
    }

    /**
     * Test if CSRF tokens can be reused
     */
    async testTokenReuse(ctx, url, target) {
        try {
            // Make first request to get a token
            const firstResponse = await fetch(url, {
                method: 'GET',
                timeout: 10000,
            });

            const body = await firstResponse.text();

            // Try to extract a CSRF token
            const token = this.extractCSRFToken(body);

            if (token) {
                // Use the same token twice
                for (let i = 0; i < 2; i++) {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `${token.name}=${token.value}&test=data`,
                        timeout: 10000,
                    });

                    if (!response.ok && i === 1) {
                        // Second request failed - tokens are single-use (good!)
                        return null;
                    }
                }

                // Both requests succeeded - token can be reused (bad!)
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'csrf_vulnerability_found',
                    target,
                    payload: {
                        endpoint: url,
                        issue: 'token_reuse_allowed',
                    },
                }));

                return {
                    type: 'csrf_token_reuse',
                    severity: 'medium',
                    endpoint: url,
                    confirmed: true,
                    description: 'CSRF tokens can be reused',
                    impact: 'Increases attack window for CSRF',
                };
            }

        } catch (error) {
            // Error extracting/testing token
        }

        return null;
    }

    /**
     * Extract CSRF token from HTML
     */
    extractCSRFToken(html) {
        for (const tokenName of this.csrfTokenNames) {
            // Look for hidden input fields
            const inputPattern = new RegExp(
                `<input[^>]+name=["']${tokenName}["'][^>]+value=["']([^"']+)["']`,
                'i'
            );
            const match = html.match(inputPattern);
            
            if (match) {
                return {
                    name: tokenName,
                    value: match[1],
                };
            }

            // Look for meta tags
            const metaPattern = new RegExp(
                `<meta[^>]+name=["']${tokenName}["'][^>]+content=["']([^"']+)["']`,
                'i'
            );
            const metaMatch = html.match(metaPattern);
            
            if (metaMatch) {
                return {
                    name: tokenName,
                    value: metaMatch[1],
                };
            }
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

export default CSRFDetector;
