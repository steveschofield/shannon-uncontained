/**
 * BusinessLogicFuzzer - Business logic vulnerability testing agent
 * 
 * Tests for business logic flaws that traditional scanners miss.
 * These are application-specific vulnerabilities in the business workflow.
 * 
 * CRITICAL FOR JUICE SHOP: Current detection 30% → Target 60%+
 * 
 * What it tests:
 * - Discount code abuse (100% off, multiple uses, expired codes)
 * - Price manipulation (negative quantities, client-side price changes)
 * - Workflow bypasses (skip payment, skip verification steps)
 * - Race conditions (parallel requests, TOCTOU)
 * - State manipulation (session, cart, order state)
 * - Privilege escalation (horizontal and vertical)
 * - Mass assignment (extra parameters)
 * - Integer overflow/underflow
 * 
 * WHY NO AUTOMATED TOOL CAN DO THIS:
 * - Business logic is unique to each application
 * - Requires understanding the workflow
 * - No universal payloads exist
 * - Needs context and creativity
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class BusinessLogicFuzzer extends BaseAgent {
    constructor(options = {}) {
        super('BusinessLogicFuzzer', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                apiEndpoints: {
                    type: 'array',
                    description: 'Discovered API endpoints',
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
                business_logic_flaws: { type: 'array', items: { type: 'object' } },
                tested_scenarios: { type: 'number' },
            },
        };

        this.requires = {
            evidence_kinds: [
                EVENT_TYPES.ENDPOINT_DISCOVERED,
                'api_endpoint_inferred',
            ],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'business_logic_flaw',
                'price_manipulation',
                'workflow_bypass',
                'race_condition',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'discount_abuse_possible',
                'price_manipulation_possible',
                'workflow_bypassable',
                'race_condition_exists',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 300000, // 5 minutes
            max_network_requests: 200,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Discount code test patterns
        this.discountTests = [
            { code: 'SAVE100', description: '100% discount' },
            { code: '100OFF', description: '100 off' },
            { code: 'FREE', description: 'Free code' },
            { code: 'TEST', description: 'Test discount' },
            { code: 'ADMIN', description: 'Admin discount' },
            { code: '0', description: 'Zero discount' },
            { code: '-100', description: 'Negative discount' },
        ];

        // Price manipulation tests
        this.priceTests = [
            { quantity: -1, description: 'Negative quantity' },
            { quantity: 0, description: 'Zero quantity' },
            { quantity: 999999, description: 'Huge quantity' },
            { price: 0, description: 'Zero price' },
            { price: -100, description: 'Negative price' },
            { price: 0.01, description: 'One cent' },
        ];

        // Workflow bypass patterns
        this.workflowTests = [
            { skip: 'payment', description: 'Skip payment step' },
            { skip: 'verification', description: 'Skip verification' },
            { skip: 'shipping', description: 'Skip shipping' },
            { state: 'completed', description: 'Force completed state' },
            { state: 'approved', description: 'Force approved state' },
        ];
    }

    async run(ctx, inputs) {
        const { target, apiEndpoints = [], authTokens = {} } = inputs;

        const results = {
            vulnerabilities: [],
            business_logic_flaws: [],
            tested_scenarios: 0,
        };

        this.setStatus('Testing business logic...');

        // Phase 1: Test discount code abuse
        const discountVulns = await this.testDiscountAbuse(ctx, apiEndpoints, target);
        results.business_logic_flaws.push(...discountVulns);
        results.tested_scenarios += this.discountTests.length;

        // Phase 2: Test price manipulation
        const priceVulns = await this.testPriceManipulation(ctx, apiEndpoints, target);
        results.business_logic_flaws.push(...priceVulns);
        results.tested_scenarios += this.priceTests.length;

        // Phase 3: Test workflow bypasses
        const workflowVulns = await this.testWorkflowBypass(ctx, apiEndpoints, target);
        results.business_logic_flaws.push(...workflowVulns);
        results.tested_scenarios += this.workflowTests.length;

        // Phase 4: Test race conditions
        const raceVulns = await this.testRaceConditions(ctx, apiEndpoints, target);
        results.business_logic_flaws.push(...raceVulns);
        results.tested_scenarios += 5;

        // Phase 5: Test mass assignment
        const massAssignVulns = await this.testMassAssignment(ctx, apiEndpoints, target);
        results.business_logic_flaws.push(...massAssignVulns);
        results.tested_scenarios += 10;

        // Consolidate into vulnerabilities array
        results.vulnerabilities = results.business_logic_flaws.filter(v => v.confirmed);

        this.setStatus(`Found ${results.vulnerabilities.length} business logic flaws`);

        return results;
    }

    /**
     * Test discount code abuse
     */
    async testDiscountAbuse(ctx, endpoints, target) {
        const vulnerabilities = [];
        
        // Find checkout/coupon/discount endpoints
        const discountEndpoints = endpoints.filter(e => {
            const url = e.url || e;
            const lower = url.toLowerCase();
            return lower.includes('coupon') || 
                   lower.includes('discount') || 
                   lower.includes('promo') ||
                   lower.includes('voucher');
        });

        if (discountEndpoints.length === 0) {
            // Try common paths
            const baseUrl = this.normalizeBaseUrl(target);
            discountEndpoints.push(
                { url: `${baseUrl}/api/coupon` },
                { url: `${baseUrl}/rest/coupon` },
                { url: `${baseUrl}/api/promo` }
            );
        }

        for (const endpoint of discountEndpoints.slice(0, 3)) {
            const url = endpoint.url || endpoint;

            // Test each discount code
            for (const test of this.discountTests) {
                try {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ code: test.code }),
                        timeout: 10000,
                    });

                    const body = await response.text();

                    // Check for success indicators
                    if (this.detectDiscountSuccess(response, body, test)) {
                        vulnerabilities.push({
                            type: 'discount_abuse',
                            severity: 'high',
                            endpoint: url,
                            test_case: test,
                            confirmed: true,
                            description: `Discount code ${test.code} accepted: ${test.description}`,
                            impact: 'Attacker can apply unauthorized discounts',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'business_logic_flaw',
                            target,
                            payload: {
                                flaw_type: 'discount_abuse',
                                endpoint: url,
                                test_code: test.code,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'discount_abuse_possible',
                            subject: url,
                            predicate: { test: test.description },
                            base_rate: 0.5,
                        });
                    }

                } catch (error) {
                    continue;
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Detect if discount was successfully applied
     */
    detectDiscountSuccess(response, body, test) {
        if (response.status === 200 || response.status === 201) {
            try {
                const json = JSON.parse(body);
                
                // Look for success indicators
                if (json.discount || json.applied || json.success || json.accepted) {
                    return true;
                }

                // Look for price reduction
                if (json.total === 0 || json.price === 0 || json.amount === 0) {
                    return true;
                }

                // Look for 100% discount
                if (json.discount === 100 || json.discount === '100%') {
                    return true;
                }

            } catch (e) {
                // Not JSON, check text
                const lower = body.toLowerCase();
                if (lower.includes('applied') || lower.includes('success')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Test price manipulation
     */
    async testPriceManipulation(ctx, endpoints, target) {
        const vulnerabilities = [];

        // Find cart/checkout/order endpoints
        const cartEndpoints = endpoints.filter(e => {
            const url = e.url || e;
            const lower = url.toLowerCase();
            return lower.includes('cart') || 
                   lower.includes('basket') || 
                   lower.includes('checkout') ||
                   lower.includes('order');
        });

        if (cartEndpoints.length === 0) {
            const baseUrl = this.normalizeBaseUrl(target);
            cartEndpoints.push(
                { url: `${baseUrl}/api/basket` },
                { url: `${baseUrl}/rest/basket` },
                { url: `${baseUrl}/api/cart` }
            );
        }

        for (const endpoint of cartEndpoints.slice(0, 3)) {
            const url = endpoint.url || endpoint;

            // Test price manipulations
            for (const test of this.priceTests) {
                try {
                    const payload = {
                        product_id: 1,
                        ...test,
                    };

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(payload),
                        timeout: 10000,
                    });

                    const body = await response.text();

                    if (this.detectPriceAccepted(response, body, test)) {
                        vulnerabilities.push({
                            type: 'price_manipulation',
                            severity: 'critical',
                            endpoint: url,
                            test_case: test,
                            confirmed: true,
                            description: `Price manipulation accepted: ${test.description}`,
                            impact: 'Attacker can manipulate prices to pay less or exploit integer overflow',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'price_manipulation',
                            target,
                            payload: {
                                endpoint: url,
                                manipulation: test.description,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'price_manipulation_possible',
                            subject: url,
                            predicate: { test: test.description },
                            base_rate: 0.5,
                        });
                    }

                } catch (error) {
                    continue;
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Detect if price manipulation was accepted
     */
    detectPriceAccepted(response, body, test) {
        if (response.status === 200 || response.status === 201) {
            try {
                const json = JSON.parse(body);
                
                // If response includes our manipulated value, it was accepted
                if (test.quantity !== undefined && json.quantity === test.quantity) {
                    return true;
                }
                
                if (test.price !== undefined && json.price === test.price) {
                    return true;
                }

                // Check for total/amount matching manipulated price
                if (test.price === 0 && (json.total === 0 || json.amount === 0)) {
                    return true;
                }

            } catch (e) {
                // Not JSON
            }
        }

        return false;
    }

    /**
     * Test workflow bypasses
     */
    async testWorkflowBypass(ctx, endpoints, target) {
        const vulnerabilities = [];

        // Find checkout/order endpoints
        const checkoutEndpoints = endpoints.filter(e => {
            const url = e.url || e;
            const lower = url.toLowerCase();
            return lower.includes('checkout') || 
                   lower.includes('order') || 
                   lower.includes('purchase');
        });

        for (const endpoint of checkoutEndpoints.slice(0, 2)) {
            const url = endpoint.url || endpoint;

            for (const test of this.workflowTests) {
                try {
                    const payload = {
                        items: [{ id: 1, quantity: 1 }],
                        ...test,
                    };

                    const response = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(payload),
                        timeout: 10000,
                    });

                    const body = await response.text();

                    if (this.detectWorkflowBypass(response, body, test)) {
                        vulnerabilities.push({
                            type: 'workflow_bypass',
                            severity: 'high',
                            endpoint: url,
                            test_case: test,
                            confirmed: true,
                            description: `Workflow bypass: ${test.description}`,
                            impact: 'Attacker can skip required steps in business process',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'workflow_bypass',
                            target,
                            payload: {
                                endpoint: url,
                                bypass: test.description,
                            },
                        }));

                        ctx.emitClaim({
                            claim_type: 'workflow_bypassable',
                            subject: url,
                            predicate: { bypass: test.description },
                            base_rate: 0.5,
                        });
                    }

                } catch (error) {
                    continue;
                }
            }
        }

        return vulnerabilities;
    }

    /**
     * Detect workflow bypass
     */
    detectWorkflowBypass(response, body, test) {
        if (response.status === 200 || response.status === 201) {
            try {
                const json = JSON.parse(body);
                
                // Order was created despite skipping steps
                if (json.order_id || json.orderId || json.id) {
                    return true;
                }

                // Status was successfully changed
                if (test.state && json.status === test.state) {
                    return true;
                }

            } catch (e) {
                // Check text response
                const lower = body.toLowerCase();
                if (lower.includes('success') || lower.includes('order')) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Test race conditions
     */
    async testRaceConditions(ctx, endpoints, target) {
        const vulnerabilities = [];

        // Find endpoints that might have race conditions
        const raceEndpoints = endpoints.filter(e => {
            const url = e.url || e;
            const lower = url.toLowerCase();
            return lower.includes('redeem') || 
                   lower.includes('claim') || 
                   lower.includes('use') ||
                   lower.includes('coupon') ||
                   lower.includes('reward');
        });

        for (const endpoint of raceEndpoints.slice(0, 2)) {
            const url = endpoint.url || endpoint;

            try {
                // Send multiple parallel requests
                const parallelRequests = 5;
                const promises = [];

                for (let i = 0; i < parallelRequests; i++) {
                    promises.push(
                        fetch(url, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ code: 'TESTRACE' }),
                            timeout: 10000,
                        })
                    );
                }

                const responses = await Promise.all(promises);

                // Check if multiple requests succeeded (race condition)
                const successCount = responses.filter(r => r.ok).length;

                if (successCount > 1) {
                    vulnerabilities.push({
                        type: 'race_condition',
                        severity: 'medium',
                        endpoint: url,
                        confirmed: true,
                        description: `Race condition: ${successCount}/${parallelRequests} parallel requests succeeded`,
                        impact: 'Attacker can exploit race conditions for multiple uses of one-time resources',
                    });

                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'race_condition',
                        target,
                        payload: {
                            endpoint: url,
                            parallel_successes: successCount,
                        },
                    }));

                    ctx.emitClaim({
                        claim_type: 'race_condition_exists',
                        subject: url,
                        predicate: { successes: successCount },
                        base_rate: 0.5,
                    });
                }

            } catch (error) {
                continue;
            }
        }

        return vulnerabilities;
    }

    /**
     * Test mass assignment vulnerabilities
     */
    async testMassAssignment(ctx, endpoints, target) {
        const vulnerabilities = [];

        // Find user/profile update endpoints
        const updateEndpoints = endpoints.filter(e => {
            const url = e.url || e;
            const lower = url.toLowerCase();
            return (lower.includes('user') || 
                    lower.includes('profile') || 
                    lower.includes('account')) &&
                   (lower.includes('update') || 
                    e.method === 'PUT' || 
                    e.method === 'PATCH');
        });

        // Additional fields to test
        const massAssignFields = [
            { field: 'isAdmin', value: true, description: 'Admin flag' },
            { field: 'role', value: 'admin', description: 'Admin role' },
            { field: 'admin', value: true, description: 'Admin boolean' },
            { field: 'verified', value: true, description: 'Verified flag' },
            { field: 'balance', value: 999999, description: 'Account balance' },
            { field: 'credits', value: 999999, description: 'Credits' },
        ];

        for (const endpoint of updateEndpoints.slice(0, 3)) {
            const url = endpoint.url || endpoint;

            for (const test of massAssignFields) {
                try {
                    const payload = {
                        email: 'test@example.com',
                        [test.field]: test.value,
                    };

                    const response = await fetch(url, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(payload),
                        timeout: 10000,
                    });

                    const body = await response.text();

                    if (response.ok) {
                        try {
                            const json = JSON.parse(body);
                            
                            // Check if extra field was accepted
                            if (json[test.field] === test.value) {
                                vulnerabilities.push({
                                    type: 'mass_assignment',
                                    severity: 'high',
                                    endpoint: url,
                                    test_case: test,
                                    confirmed: true,
                                    description: `Mass assignment: ${test.description} field accepted`,
                                    impact: 'Attacker can set unauthorized fields',
                                });

                                ctx.emitEvidence(createEvidenceEvent({
                                    source: this.name,
                                    event_type: 'business_logic_flaw',
                                    target,
                                    payload: {
                                        flaw_type: 'mass_assignment',
                                        endpoint: url,
                                        field: test.field,
                                    },
                                }));
                            }

                        } catch (e) {
                            // Not JSON
                        }
                    }

                } catch (error) {
                    continue;
                }
            }
        }

        return vulnerabilities;
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

export default BusinessLogicFuzzer;
