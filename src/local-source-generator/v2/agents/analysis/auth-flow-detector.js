/**
 * AuthFlowDetector - Authentication Flow Detection Agent
 * 
 * Detects and maps authentication mechanisms without source code access.
 * Critical for blackbox testing - enables testing of authenticated endpoints.
 * 
 * Capabilities:
 * - Detects login forms (HTML, JSON API, OAuth, SAML)
 * - Extracts session tokens (cookies, headers, localStorage)
 * - Maps authentication flows (login → session → authenticated requests)
 * - Detects multi-factor authentication
 * - Identifies password reset flows
 * - Discovers API authentication schemes (Bearer, Basic, JWT)
 */

import { BaseAgent } from '../base-agent.js';
import { EVENT_TYPES, createEvidenceEvent } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';
import { load } from 'cheerio';

export class AuthFlowDetector extends BaseAgent {
    constructor(options = {}) {
        super('AuthFlowDetector', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { 
                    type: 'string', 
                    description: 'Target URL' 
                },
                test_credentials: {
                    type: 'object',
                    description: 'Optional test credentials for flow mapping',
                    properties: {
                        username: { type: 'string' },
                        password: { type: 'string' }
                    }
                },
                authentication: {
                    type: 'object',
                    description: 'Optional authentication config from user settings',
                    properties: {
                        login_type: { type: 'string' },
                        login_url: { type: 'string' },
                        credentials: {
                            type: 'object',
                            properties: {
                                username: { type: 'string' },
                                password: { type: 'string' },
                                totp_secret: { type: 'string' }
                            }
                        },
                        login_flow: { type: 'array', items: { type: 'string' } },
                        success_condition: { type: 'object' }
                    }
                },
                follow_redirects: {
                    type: 'boolean',
                    default: true,
                    description: 'Follow redirects during flow detection'
                }
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                auth_mechanisms: { 
                    type: 'array',
                    description: 'Detected authentication mechanisms'
                },
                login_endpoints: { 
                    type: 'array',
                    description: 'Discovered login endpoints'
                },
                session_tokens: {
                    type: 'array',
                    description: 'Identified session token locations'
                },
                auth_flows: {
                    type: 'array',
                    description: 'Mapped authentication flows'
                },
                api_auth_schemes: {
                    type: 'array',
                    description: 'API authentication schemes detected'
                }
            },
        };

        this.requires = { 
            evidence_kinds: ['endpoint_discovered', 'crawl_result'], 
            model_nodes: ['endpoint'] 
        };

        this.emits = {
            evidence_events: [
                EVENT_TYPES.ENDPOINT_DISCOVERED,
                'auth_mechanism_detected',
                'session_token_identified',
                'auth_flow_mapped',
                'login_form_detected',
                'api_auth_detected'
            ],
            model_updates: ['auth_endpoint', 'session_mechanism'],
            claims: [
                CLAIM_TYPES.AUTHENTICATION_REQUIRED,
                'auth_mechanism_type',
                'session_token_location'
            ],
            artifacts: ['auth_flow_diagram.md'],
        };

        this.default_budget = {
            max_time_ms: 120000,  // 2 minutes
            max_network_requests: 200,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Common login paths to probe
        this.commonLoginPaths = [
            '/login',
            '/signin',
            '/sign-in',
            '/auth/login',
            '/api/login',
            '/api/auth/login',
            '/api/v1/login',
            '/api/v1/auth/login',
            '/users/login',
            '/user/login',
            '/session/new',
            '/authenticate',
            '/auth',
            '/oauth/authorize',
            '/saml/login',
            '/sso/login',
            '/rest/auth/login',
            '/graphql', // May require auth
            '/.well-known/openid-configuration', // OAuth/OIDC discovery
        ];

        // Common form field patterns
        this.loginFieldPatterns = {
            username: [
                'username', 'user', 'email', 'login', 'account', 
                'user_name', 'user-name', 'emailAddress', 'mail',
                'userid', 'user_id', 'loginid', 'login_id'
            ],
            password: [
                'password', 'pass', 'passwd', 'pwd', 'secret',
                'user_password', 'user-password', 'userPassword'
            ],
            token: [
                'token', '_token', 'csrf_token', 'authenticity_token',
                'csrf-token', 'xsrf-token', '_csrf'
            ],
            mfa: [
                'code', 'otp', 'mfa', 'verification', 'verify',
                'two_factor', 'twoFactor', '2fa', 'totp'
            ]
        };

        // API auth header patterns
        this.authHeaderPatterns = [
            'Authorization',
            'X-Auth-Token',
            'X-API-Key',
            'X-Access-Token',
            'X-Session-Token',
            'Bearer',
            'API-Key',
            'apikey'
        ];
    }

    async run(ctx, inputs) {
        const { target, follow_redirects = true } = inputs;
        const authConfig = inputs.authentication || null;
        const test_credentials = inputs.test_credentials || authConfig?.credentials || null;
        const baseUrl = this.normalizeBaseUrl(target);

        const results = {
            auth_mechanisms: [],
            login_endpoints: [],
            session_tokens: [],
            auth_flows: [],
            api_auth_schemes: []
        };

        this.setStatus('Starting authentication flow detection...');

        // Phase 1: Discover login endpoints
        const loginEndpoints = await this.discoverLoginEndpoints(ctx, baseUrl);
        const seededLogin = this.normalizeLoginEndpoint(authConfig?.login_url || authConfig?.loginUrl, baseUrl);
        if (seededLogin && !loginEndpoints.some(endpoint => endpoint.url === seededLogin.url)) {
            loginEndpoints.unshift(seededLogin);
            ctx.logEvent?.({
                type: 'auth_login_seeded',
                agent: this.name,
                login_url: seededLogin.url,
                source: 'config'
            });
        }
        results.login_endpoints = loginEndpoints;

        // Phase 2: Analyze each login endpoint
        for (const endpoint of loginEndpoints) {
            this.setStatus(`Analyzing login endpoint: ${endpoint.url}`);
            
            const mechanism = await this.analyzeLoginEndpoint(ctx, endpoint, baseUrl);
            if (mechanism) {
                results.auth_mechanisms.push(mechanism);
                
                // Emit evidence
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'auth_mechanism_detected',
                    target,
                    payload: mechanism
                }));
            }
        }

        // Phase 3: Detect API authentication schemes
        const apiSchemes = await this.detectAPIAuthSchemes(ctx, baseUrl);
        results.api_auth_schemes = apiSchemes;

        // Phase 4: Map authentication flows (if test credentials provided)
        if (test_credentials && results.auth_mechanisms.length > 0) {
            this.setStatus('Mapping authentication flows with test credentials...');
            
            const flows = await this.mapAuthFlows(
                ctx, 
                results.auth_mechanisms, 
                test_credentials,
                baseUrl
            );
            results.auth_flows = flows;
        }

        // Phase 5: Detect session token mechanisms
        const sessionTokens = await this.detectSessionTokens(ctx, results.auth_mechanisms);
        results.session_tokens = sessionTokens;

        // Emit summary claim
        if (results.auth_mechanisms.length > 0) {
            ctx.emitClaim({
                claim_type: CLAIM_TYPES.AUTHENTICATION_REQUIRED,
                subject: target,
                predicate: {
                    mechanisms: results.auth_mechanisms.map(m => m.type),
                    endpoints: results.login_endpoints.map(e => e.url)
                },
                base_rate: 0.9, // High confidence if we found login forms
            });
        }

        this.setStatus(`Detection complete: ${results.auth_mechanisms.length} mechanisms found`);
        return results;
    }

    normalizeLoginEndpoint(loginUrl, baseUrl) {
        if (!loginUrl) return null;
        try {
            if (loginUrl.startsWith('http://') || loginUrl.startsWith('https://')) {
                const parsed = new URL(loginUrl);
                return {
                    url: loginUrl,
                    path: parsed.pathname || '/login',
                    method: 'POST'
                };
            }
            const path = loginUrl.startsWith('/') ? loginUrl : `/${loginUrl}`;
            return {
                url: `${baseUrl}${path}`,
                path,
                method: 'POST'
            };
        } catch {
            return null;
        }
    }

    /**
     * Discover login endpoints by probing common paths and analyzing crawled pages
     */
    async discoverLoginEndpoints(ctx, baseUrl) {
        const endpoints = [];
        const seen = new Set();

        // Strategy 1: Probe common login paths
        for (const path of this.commonLoginPaths) {
            if (seen.has(path)) continue;
            
            const url = `${baseUrl}${path}`;
            ctx.recordNetworkRequest();

            try {
                const response = await fetch(url, {
                    method: 'GET',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/json,*/*'
                    },
                    redirect: 'manual',
                    timeout: 10000
                });

                // Success or redirect = potential login page
                if (response.ok || response.status === 302 || response.status === 301) {
                    endpoints.push({
                        url,
                        path,
                        status: response.status,
                        contentType: response.headers.get('content-type'),
                        source: 'common_path_probe'
                    });
                    seen.add(path);

                    // Emit evidence
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: EVENT_TYPES.ENDPOINT_DISCOVERED,
                        target: baseUrl,
                        payload: {
                            url,
                            method: 'GET',
                            status: response.status,
                            purpose: 'authentication',
                            discovery_method: 'common_path'
                        }
                    }));
                }
            } catch (error) {
                // Silent fail - endpoint doesn't exist
            }
        }

        // Strategy 2: Analyze crawled pages from CrawlerAgent
        const crawlResults = ctx.evidenceGraph.getEventsByType('crawl_result');
        for (const event of crawlResults) {
            const html = event.payload?.html || event.payload?.body;
            if (html && typeof html === 'string') {
                const loginEndpoint = this.extractLoginFormFromHTML(html, baseUrl);
                if (loginEndpoint && !seen.has(loginEndpoint.path)) {
                    endpoints.push({
                        ...loginEndpoint,
                        source: 'html_form_extraction'
                    });
                    seen.add(loginEndpoint.path);
                }
            }
        }

        // Strategy 3: Check discovered endpoints for auth-related names
        const discoveredEndpoints = ctx.evidenceGraph.getEventsByType(EVENT_TYPES.ENDPOINT_DISCOVERED);
        for (const event of discoveredEndpoints) {
            const path = event.payload?.path || event.payload?.url;
            if (path && this.looksLikeAuthEndpoint(path) && !seen.has(path)) {
                endpoints.push({
                    url: path.startsWith('http') ? path : `${baseUrl}${path}`,
                    path: path.startsWith('http') ? new URL(path).pathname : path,
                    source: 'endpoint_name_heuristic'
                });
                seen.add(path);
            }
        }

        return endpoints;
    }

    /**
     * Analyze a login endpoint to determine authentication mechanism
     */
    async analyzeLoginEndpoint(ctx, endpoint, baseUrl) {
        ctx.recordNetworkRequest();

        try {
            const response = await fetch(endpoint.url, {
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/json,*/*'
                },
                timeout: 10000
            });

            const contentType = response.headers.get('content-type') || '';
            const body = await response.text();

            // HTML form-based authentication
            if (contentType.includes('text/html')) {
                return this.analyzeHTMLLoginForm(body, endpoint.url, ctx);
            }

            // JSON API authentication
            if (contentType.includes('application/json')) {
                return this.analyzeJSONAuthAPI(body, endpoint.url, ctx);
            }

            // OAuth/OIDC
            if (endpoint.path.includes('oauth') || endpoint.path.includes('openid')) {
                return this.analyzeOAuthEndpoint(endpoint.url, ctx);
            }

            // SAML
            if (endpoint.path.includes('saml')) {
                return {
                    type: 'saml',
                    url: endpoint.url,
                    mechanism: 'SAML 2.0',
                    confidence: 0.8
                };
            }

        } catch (error) {
            // Endpoint unreachable or error
        }

        return null;
    }

    /**
     * Analyze HTML login form
     */
    analyzeHTMLLoginForm(html, url, ctx) {
        const $ = load(html);
        const forms = $('form');

        for (let i = 0; i < forms.length; i++) {
            const form = $(forms[i]);
            const action = form.attr('action') || '';
            const method = (form.attr('method') || 'GET').toUpperCase();

            // Look for login-related inputs
            const inputs = form.find('input');
            const fields = {
                username: null,
                password: null,
                csrf: null,
                mfa: null
            };

            inputs.each((_, input) => {
                const $input = $(input);
                const name = $input.attr('name') || '';
                const type = $input.attr('type') || 'text';
                const id = $input.attr('id') || '';
                const nameLower = name.toLowerCase();
                const idLower = id.toLowerCase();

                // Check for username field
                if (this.matchesPattern(nameLower, this.loginFieldPatterns.username) ||
                    this.matchesPattern(idLower, this.loginFieldPatterns.username)) {
                    fields.username = { name, type, id };
                }

                // Check for password field
                if (type === 'password' || 
                    this.matchesPattern(nameLower, this.loginFieldPatterns.password)) {
                    fields.password = { name, type, id };
                }

                // Check for CSRF token
                if (type === 'hidden' && 
                    this.matchesPattern(nameLower, this.loginFieldPatterns.token)) {
                    fields.csrf = { name, type, id, value: $input.attr('value') };
                }

                // Check for MFA field
                if (this.matchesPattern(nameLower, this.loginFieldPatterns.mfa) ||
                    this.matchesPattern(idLower, this.loginFieldPatterns.mfa)) {
                    fields.mfa = { name, type, id };
                }
            });

            // If we found username + password, this is likely a login form
            if (fields.username && fields.password) {
                const mechanism = {
                    type: 'html_form',
                    url,
                    method,
                    action,
                    fields: {
                        username: fields.username.name,
                        password: fields.password.name,
                        csrf: fields.csrf?.name || null
                    },
                    has_mfa: !!fields.mfa,
                    csrf_protected: !!fields.csrf,
                    confidence: 0.95
                };

                // Emit login form detection
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'login_form_detected',
                    target: url,
                    payload: mechanism
                }));

                return mechanism;
            }
        }

        return null;
    }

    /**
     * Analyze JSON API authentication endpoint
     */
    analyzeJSONAuthAPI(body, url, ctx) {
        try {
            const json = JSON.parse(body);

            // Common API auth response patterns
            const hasAuthFields = (obj) => {
                const keys = Object.keys(obj).map(k => k.toLowerCase());
                return keys.some(k => 
                    k.includes('token') || 
                    k.includes('auth') || 
                    k.includes('session') ||
                    k.includes('jwt')
                );
            };

            if (hasAuthFields(json)) {
                const mechanism = {
                    type: 'json_api',
                    url,
                    method: 'POST',
                    expected_fields: ['username', 'password', 'email'],
                    response_contains: Object.keys(json),
                    confidence: 0.85
                };

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'api_auth_detected',
                    target: url,
                    payload: mechanism
                }));

                return mechanism;
            }
        } catch (e) {
            // Not valid JSON
        }

        return null;
    }

    /**
     * Analyze OAuth/OIDC endpoint
     */
    async analyzeOAuthEndpoint(url, ctx) {
        // Try to fetch OpenID configuration
        const baseUrl = new URL(url).origin;
        const configUrl = `${baseUrl}/.well-known/openid-configuration`;

        try {
            ctx.recordNetworkRequest();
            const response = await fetch(configUrl, { timeout: 5000 });
            
            if (response.ok) {
                const config = await response.json();
                return {
                    type: 'oauth2_oidc',
                    url,
                    authorization_endpoint: config.authorization_endpoint,
                    token_endpoint: config.token_endpoint,
                    issuer: config.issuer,
                    confidence: 0.95
                };
            }
        } catch (e) {
            // Config not available
        }

        // Fallback to generic OAuth detection
        return {
            type: 'oauth2',
            url,
            mechanism: 'OAuth 2.0',
            confidence: 0.7
        };
    }

    /**
     * Detect API authentication schemes by analyzing HTTP headers
     */
    async detectAPIAuthSchemes(ctx, baseUrl) {
        const schemes = [];

        // Get API endpoints from evidence
        const apiEndpoints = ctx.evidenceGraph.getEventsByType(EVENT_TYPES.ENDPOINT_DISCOVERED)
            .filter(e => {
                const path = e.payload?.path || '';
                return path.includes('/api') || path.includes('/graphql') || path.includes('/rest');
            })
            .slice(0, 10); // Sample first 10 API endpoints

        for (const endpoint of apiEndpoints) {
            const url = endpoint.payload?.url || `${baseUrl}${endpoint.payload?.path}`;
            
            try {
                ctx.recordNetworkRequest();
                const response = await fetch(url, {
                    method: 'GET',
                    timeout: 5000
                });

                // Check WWW-Authenticate header
                const wwwAuth = response.headers.get('www-authenticate');
                if (wwwAuth) {
                    const scheme = this.parseWWWAuthenticate(wwwAuth);
                    if (scheme && !schemes.find(s => s.type === scheme.type)) {
                        schemes.push(scheme);
                        
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'api_auth_detected',
                            target: baseUrl,
                            payload: scheme
                        }));
                    }
                }

                // Check for common auth headers in OPTIONS
                ctx.recordNetworkRequest();
                const optionsResponse = await fetch(url, {
                    method: 'OPTIONS',
                    timeout: 5000
                });

                const allowHeaders = optionsResponse.headers.get('access-control-allow-headers');
                if (allowHeaders) {
                    const authHeaders = this.authHeaderPatterns.filter(pattern =>
                        allowHeaders.toLowerCase().includes(pattern.toLowerCase())
                    );

                    if (authHeaders.length > 0 && !schemes.find(s => s.type === 'api_key')) {
                        schemes.push({
                            type: 'api_key',
                            headers: authHeaders,
                            confidence: 0.8
                        });
                    }
                }

            } catch (error) {
                // Endpoint unavailable
            }
        }

        return schemes;
    }

    /**
     * Map complete authentication flows (requires test credentials)
     */
    async mapAuthFlows(ctx, mechanisms, credentials, baseUrl) {
        const flows = [];

        for (const mechanism of mechanisms) {
            try {
                const flow = await this.testAuthFlow(ctx, mechanism, credentials, baseUrl);
                if (flow) {
                    flows.push(flow);
                    
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'auth_flow_mapped',
                        target: baseUrl,
                        payload: flow
                    }));
                }
            } catch (error) {
                // Flow mapping failed
            }
        }

        return flows;
    }

    /**
     * Test an authentication flow with credentials
     */
    async testAuthFlow(ctx, mechanism, credentials, baseUrl) {
        if (mechanism.type === 'html_form') {
            return await this.testHTMLFormFlow(ctx, mechanism, credentials, baseUrl);
        }

        if (mechanism.type === 'json_api') {
            return await this.testJSONAPIFlow(ctx, mechanism, credentials, baseUrl);
        }

        return null;
    }

    /**
     * Test HTML form authentication flow
     */
    async testHTMLFormFlow(ctx, mechanism, credentials, baseUrl) {
        ctx.recordNetworkRequest();

        const formData = new URLSearchParams();
        formData.append(mechanism.fields.username, credentials.username);
        formData.append(mechanism.fields.password, credentials.password);
        
        if (mechanism.fields.csrf && mechanism.csrf_protected) {
            // Would need to fetch the form first to get CSRF token
            // For now, we just document the requirement
        }

        try {
            const response = await fetch(mechanism.url, {
                method: mechanism.method,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                body: formData,
                redirect: 'manual',
                timeout: 10000
            });

            // Extract session tokens
            const cookies = response.headers.raw()['set-cookie'] || [];
            const sessionTokens = cookies.filter(c => 
                c.toLowerCase().includes('session') || 
                c.toLowerCase().includes('token') ||
                c.toLowerCase().includes('auth')
            );

            return {
                mechanism_type: 'html_form',
                steps: [
                    {
                        step: 1,
                        action: 'GET login form',
                        url: mechanism.url,
                        extracts: mechanism.csrf_protected ? ['csrf_token'] : []
                    },
                    {
                        step: 2,
                        action: 'POST credentials',
                        url: mechanism.url,
                        method: mechanism.method,
                        body: {
                            [mechanism.fields.username]: '<username>',
                            [mechanism.fields.password]: '<password>',
                            ...(mechanism.fields.csrf ? { [mechanism.fields.csrf]: '<csrf_token>' } : {})
                        }
                    },
                    {
                        step: 3,
                        action: 'Receive session token',
                        location: 'Set-Cookie header',
                        tokens: sessionTokens.map(c => c.split(';')[0])
                    }
                ],
                session_tokens: sessionTokens.length > 0 ? sessionTokens : null,
                redirect_status: response.status,
                redirect_location: response.headers.get('location'),
                tested: true,
                test_result: response.ok || response.status === 302 ? 'success' : 'failure'
            };
        } catch (error) {
            return {
                mechanism_type: 'html_form',
                tested: false,
                error: error.message
            };
        }
    }

    /**
     * Test JSON API authentication flow
     */
    async testJSONAPIFlow(ctx, mechanism, credentials, baseUrl) {
        ctx.recordNetworkRequest();

        const body = JSON.stringify({
            username: credentials.username,
            password: credentials.password
        });

        try {
            const response = await fetch(mechanism.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body,
                timeout: 10000
            });

            const data = await response.json();

            // Extract tokens from response
            const tokens = this.extractTokensFromJSON(data);

            return {
                mechanism_type: 'json_api',
                steps: [
                    {
                        step: 1,
                        action: 'POST credentials',
                        url: mechanism.url,
                        method: 'POST',
                        body: {
                            username: '<username>',
                            password: '<password>'
                        }
                    },
                    {
                        step: 2,
                        action: 'Receive authentication token',
                        location: 'Response body (JSON)',
                        tokens: tokens
                    },
                    {
                        step: 3,
                        action: 'Use token in subsequent requests',
                        header: 'Authorization: Bearer <token>',
                        note: 'Include token in all authenticated API requests'
                    }
                ],
                tokens,
                tested: true,
                test_result: response.ok ? 'success' : 'failure'
            };
        } catch (error) {
            return {
                mechanism_type: 'json_api',
                tested: false,
                error: error.message
            };
        }
    }

    /**
     * Detect session token mechanisms from auth mechanisms
     */
    async detectSessionTokens(ctx, mechanisms) {
        const tokens = [];
        const seen = new Set();

        for (const mechanism of mechanisms) {
            // HTML forms typically use cookies
            if (mechanism.type === 'html_form') {
                if (!seen.has('cookie')) {
                    tokens.push({
                        type: 'cookie',
                        location: 'Set-Cookie header',
                        mechanism: 'HTTP Cookie',
                        common_names: ['session', 'sessionid', 'sess', 'PHPSESSID', 'connect.sid'],
                        confidence: 0.9
                    });
                    seen.add('cookie');
                }
            }

            // JSON APIs typically use Bearer tokens
            if (mechanism.type === 'json_api') {
                if (!seen.has('bearer')) {
                    tokens.push({
                        type: 'bearer_token',
                        location: 'Authorization header',
                        mechanism: 'Bearer Token (JWT)',
                        format: 'Authorization: Bearer <token>',
                        confidence: 0.9
                    });
                    seen.add('bearer');
                }
            }

            // OAuth uses access tokens
            if (mechanism.type === 'oauth2' || mechanism.type === 'oauth2_oidc') {
                if (!seen.has('oauth_token')) {
                    tokens.push({
                        type: 'oauth_access_token',
                        location: 'Authorization header or URL parameter',
                        mechanism: 'OAuth 2.0 Access Token',
                        formats: [
                            'Authorization: Bearer <access_token>',
                            '?access_token=<token>'
                        ],
                        confidence: 0.95
                    });
                    seen.add('oauth_token');
                }
            }
        }

        // Emit evidence for each token type
        for (const token of tokens) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: 'session_token_identified',
                target: 'session_mechanism',
                payload: token
            }));
        }

        return tokens;
    }

    /**
     * Helper: Check if path looks like auth endpoint
     */
    looksLikeAuthEndpoint(path) {
        const authKeywords = [
            'login', 'signin', 'auth', 'authenticate', 'session',
            'oauth', 'saml', 'sso', 'token', 'jwt'
        ];
        const pathLower = path.toLowerCase();
        return authKeywords.some(keyword => pathLower.includes(keyword));
    }

    /**
     * Helper: Extract login form from HTML
     */
    extractLoginFormFromHTML(html, baseUrl) {
        const $ = load(html);
        const forms = $('form');

        for (let i = 0; i < forms.length; i++) {
            const form = $(forms[i]);
            const inputs = form.find('input');
            
            let hasPassword = false;
            let hasUsername = false;

            inputs.each((_, input) => {
                const type = $(input).attr('type') || 'text';
                const name = ($(input).attr('name') || '').toLowerCase();
                
                if (type === 'password') hasPassword = true;
                if (this.matchesPattern(name, this.loginFieldPatterns.username)) hasUsername = true;
            });

            if (hasPassword && hasUsername) {
                const action = form.attr('action') || '';
                const method = form.attr('method') || 'POST';
                const path = action.startsWith('http') ? new URL(action).pathname : action;
                
                return {
                    url: action.startsWith('http') ? action : `${baseUrl}${action || '/login'}`,
                    path,
                    method: method.toUpperCase()
                };
            }
        }

        return null;
    }

    /**
     * Helper: Check if string matches pattern list
     */
    matchesPattern(str, patterns) {
        return patterns.some(pattern => str.includes(pattern));
    }

    /**
     * Helper: Parse WWW-Authenticate header
     */
    parseWWWAuthenticate(header) {
        const lower = header.toLowerCase();
        
        if (lower.startsWith('basic')) {
            return { type: 'basic', mechanism: 'HTTP Basic Authentication', confidence: 1.0 };
        }
        if (lower.startsWith('bearer')) {
            return { type: 'bearer', mechanism: 'Bearer Token', confidence: 1.0 };
        }
        if (lower.startsWith('digest')) {
            return { type: 'digest', mechanism: 'HTTP Digest Authentication', confidence: 1.0 };
        }
        if (lower.includes('oauth')) {
            return { type: 'oauth', mechanism: 'OAuth', confidence: 0.9 };
        }

        return null;
    }

    /**
     * Helper: Extract tokens from JSON response
     */
    extractTokensFromJSON(data, prefix = '') {
        const tokens = [];
        
        const traverse = (obj, path = '') => {
            if (!obj || typeof obj !== 'object') return;
            
            for (const [key, value] of Object.entries(obj)) {
                const fullPath = path ? `${path}.${key}` : key;
                const keyLower = key.toLowerCase();
                
                // Check if this looks like a token
                if ((keyLower.includes('token') || 
                     keyLower.includes('jwt') || 
                     keyLower.includes('auth') ||
                     keyLower === 'access_token' ||
                     keyLower === 'id_token' ||
                     keyLower === 'refresh_token') && 
                    typeof value === 'string') {
                    tokens.push({
                        field: fullPath,
                        type: this.inferTokenType(key),
                        sample: value.length > 20 ? value.substring(0, 20) + '...' : value,
                        value
                    });
                }
                
                // Recurse into nested objects
                if (typeof value === 'object') {
                    traverse(value, fullPath);
                }
            }
        };
        
        traverse(data);
        return tokens;
    }

    /**
     * Helper: Infer token type from field name
     */
    inferTokenType(fieldName) {
        const lower = fieldName.toLowerCase();
        if (lower.includes('jwt')) return 'JWT';
        if (lower.includes('access')) return 'access_token';
        if (lower.includes('refresh')) return 'refresh_token';
        if (lower.includes('id_token')) return 'id_token';
        return 'generic_token';
    }

    /**
     * Helper: Normalize base URL
     */
    normalizeBaseUrl(target) {
        try {
            const url = new URL(target);
            return `${url.protocol}//${url.host}`;
        } catch {
            return target;
        }
    }
}

export default AuthFlowDetector;
