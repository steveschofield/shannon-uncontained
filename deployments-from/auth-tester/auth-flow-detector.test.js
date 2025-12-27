/**
 * AuthFlowDetector - Test Suite
 * 
 * Tests authentication flow detection capabilities
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';
import { AuthFlowDetector } from './auth-flow-detector.js';
import { AgentContext } from '../base-agent.js';
import { EvidenceGraph, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { TargetModel } from '../../worldmodel/target-model.js';
import { EpistemicLedger } from '../../epistemics/ledger.js';

describe('AuthFlowDetector', () => {
    
    test('should initialize with correct schema', () => {
        const agent = new AuthFlowDetector();
        
        assert.strictEqual(agent.name, 'AuthFlowDetector');
        assert.ok(agent.inputs_schema);
        assert.ok(agent.outputs_schema);
        assert.strictEqual(agent.inputs_schema.required[0], 'target');
    });

    test('should detect common login paths', () => {
        const agent = new AuthFlowDetector();
        
        // Check that common paths are configured
        assert.ok(agent.commonLoginPaths.includes('/login'));
        assert.ok(agent.commonLoginPaths.includes('/signin'));
        assert.ok(agent.commonLoginPaths.includes('/api/login'));
        assert.ok(agent.commonLoginPaths.includes('/auth'));
    });

    test('should identify auth-related endpoints by name', () => {
        const agent = new AuthFlowDetector();
        
        // Test path heuristics
        assert.ok(agent.looksLikeAuthEndpoint('/login'));
        assert.ok(agent.looksLikeAuthEndpoint('/api/auth/signin'));
        assert.ok(agent.looksLikeAuthEndpoint('/oauth/authorize'));
        assert.ok(agent.looksLikeAuthEndpoint('/session/new'));
        
        // Should not match random endpoints
        assert.ok(!agent.looksLikeAuthEndpoint('/api/users'));
        assert.ok(!agent.looksLikeAuthEndpoint('/products'));
    });

    test('should match login field patterns', () => {
        const agent = new AuthFlowDetector();
        
        // Username patterns
        assert.ok(agent.matchesPattern('username', agent.loginFieldPatterns.username));
        assert.ok(agent.matchesPattern('email', agent.loginFieldPatterns.username));
        assert.ok(agent.matchesPattern('user_name', agent.loginFieldPatterns.username));
        
        // Password patterns
        assert.ok(agent.matchesPattern('password', agent.loginFieldPatterns.password));
        assert.ok(agent.matchesPattern('passwd', agent.loginFieldPatterns.password));
        assert.ok(agent.matchesPattern('pwd', agent.loginFieldPatterns.password));
        
        // CSRF token patterns
        assert.ok(agent.matchesPattern('csrf_token', agent.loginFieldPatterns.token));
        assert.ok(agent.matchesPattern('_token', agent.loginFieldPatterns.token));
        assert.ok(agent.matchesPattern('authenticity_token', agent.loginFieldPatterns.token));
    });

    test('should extract login form from HTML', () => {
        const agent = new AuthFlowDetector();
        
        const html = `
            <html>
                <body>
                    <form action="/login" method="POST">
                        <input type="text" name="username" />
                        <input type="password" name="password" />
                        <button type="submit">Login</button>
                    </form>
                </body>
            </html>
        `;
        
        const result = agent.extractLoginFormFromHTML(html, 'https://example.com');
        
        assert.ok(result);
        assert.strictEqual(result.method, 'POST');
        assert.ok(result.url.includes('/login'));
    });

    test('should extract form with email instead of username', () => {
        const agent = new AuthFlowDetector();
        
        const html = `
            <form action="/signin" method="POST">
                <input type="email" name="email" />
                <input type="password" name="pass" />
            </form>
        `;
        
        const result = agent.extractLoginFormFromHTML(html, 'https://example.com');
        
        assert.ok(result);
        assert.strictEqual(result.method, 'POST');
    });

    test('should parse WWW-Authenticate header', () => {
        const agent = new AuthFlowDetector();
        
        // Test Basic auth
        let result = agent.parseWWWAuthenticate('Basic realm="Secure Area"');
        assert.strictEqual(result.type, 'basic');
        assert.strictEqual(result.confidence, 1.0);
        
        // Test Bearer auth
        result = agent.parseWWWAuthenticate('Bearer realm="example"');
        assert.strictEqual(result.type, 'bearer');
        
        // Test Digest auth
        result = agent.parseWWWAuthenticate('Digest realm="example"');
        assert.strictEqual(result.type, 'digest');
    });

    test('should extract tokens from JSON response', () => {
        const agent = new AuthFlowDetector();
        
        const jsonData = {
            success: true,
            data: {
                user: {
                    id: 123,
                    name: 'Test User'
                },
                access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                refresh_token: 'refresh_abc123...',
                token_type: 'Bearer'
            }
        };
        
        const tokens = agent.extractTokensFromJSON(jsonData);
        
        assert.ok(tokens.length >= 2);
        assert.ok(tokens.some(t => t.field === 'data.access_token'));
        assert.ok(tokens.some(t => t.field === 'data.refresh_token'));
    });

    test('should infer token types correctly', () => {
        const agent = new AuthFlowDetector();
        
        assert.strictEqual(agent.inferTokenType('access_token'), 'access_token');
        assert.strictEqual(agent.inferTokenType('refresh_token'), 'refresh_token');
        assert.strictEqual(agent.inferTokenType('id_token'), 'id_token');
        assert.strictEqual(agent.inferTokenType('jwt'), 'JWT');
        assert.strictEqual(agent.inferTokenType('some_token'), 'generic_token');
    });

    test('should normalize base URLs', () => {
        const agent = new AuthFlowDetector();
        
        assert.strictEqual(
            agent.normalizeBaseUrl('https://example.com/some/path'),
            'https://example.com'
        );
        assert.strictEqual(
            agent.normalizeBaseUrl('http://localhost:3000/login'),
            'http://localhost:3000'
        );
        assert.strictEqual(
            agent.normalizeBaseUrl('https://api.example.com:8443/'),
            'https://api.example.com:8443'
        );
    });

    test('should detect HTML login form mechanism', () => {
        const agent = new AuthFlowDetector();
        
        const html = `
            <form action="/login" method="POST">
                <input type="text" name="username" id="user" />
                <input type="password" name="password" id="pass" />
                <input type="hidden" name="_csrf" value="token123" />
                <button type="submit">Sign In</button>
            </form>
        `;
        
        // Create minimal context
        const evidenceGraph = new EvidenceGraph();
        const targetModel = new TargetModel();
        const ledger = new EpistemicLedger();
        
        const ctx = new AgentContext({
            evidenceGraph,
            targetModel,
            ledger,
            config: {},
            budget: {}
        });
        
        const mechanism = agent.analyzeHTMLLoginForm(html, 'https://example.com/login', ctx);
        
        assert.ok(mechanism);
        assert.strictEqual(mechanism.type, 'html_form');
        assert.strictEqual(mechanism.method, 'POST');
        assert.strictEqual(mechanism.fields.username, 'username');
        assert.strictEqual(mechanism.fields.password, 'password');
        assert.strictEqual(mechanism.fields.csrf, '_csrf');
        assert.ok(mechanism.csrf_protected);
        assert.strictEqual(mechanism.confidence, 0.95);
    });

    test('should handle form without CSRF protection', () => {
        const agent = new AuthFlowDetector();
        
        const html = `
            <form action="/login">
                <input name="user" />
                <input type="password" name="pass" />
            </form>
        `;
        
        const evidenceGraph = new EvidenceGraph();
        const targetModel = new TargetModel();
        const ledger = new EpistemicLedger();
        
        const ctx = new AgentContext({
            evidenceGraph,
            targetModel,
            ledger,
            config: {},
            budget: {}
        });
        
        const mechanism = agent.analyzeHTMLLoginForm(html, 'https://example.com/login', ctx);
        
        assert.ok(mechanism);
        assert.ok(!mechanism.csrf_protected);
        assert.strictEqual(mechanism.fields.csrf, null);
    });

    test('should handle JSON auth API', () => {
        const agent = new AuthFlowDetector();
        
        const jsonBody = JSON.stringify({
            message: 'Please authenticate',
            fields: ['username', 'password'],
            token_required: true,
            session_endpoint: '/api/session'
        });
        
        const evidenceGraph = new EvidenceGraph();
        const targetModel = new TargetModel();
        const ledger = new EpistemicLedger();
        
        const ctx = new AgentContext({
            evidenceGraph,
            targetModel,
            ledger,
            config: {},
            budget: {}
        });
        
        const mechanism = agent.analyzeJSONAuthAPI(jsonBody, 'https://api.example.com/auth', ctx);
        
        assert.ok(mechanism);
        assert.strictEqual(mechanism.type, 'json_api');
        assert.strictEqual(mechanism.method, 'POST');
        assert.ok(mechanism.response_contains.includes('token_required'));
    });
});

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log('Running AuthFlowDetector tests...');
}
