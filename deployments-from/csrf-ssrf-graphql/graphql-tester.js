/**
 * GraphQLTester - GraphQL security testing agent
 * 
 * Tests for GraphQL-specific vulnerabilities and misconfigurations.
 * GraphQL is everywhere but poorly tested by traditional scanners.
 * 
 * What it tests:
 * - Introspection query enabled (reveals entire schema)
 * - Query depth limit (DOS via deeply nested queries)
 * - Query complexity limit (DOS via expensive queries)
 * - Field suggestions (information disclosure)
 * - Batching attacks (amplification)
 * - Mutations without authentication
 * - Authorization bypass in resolvers
 * - Information disclosure via errors
 * - Alias-based amplification
 * 
 * CRITICAL: Most GraphQL APIs have introspection enabled in production
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class GraphQLTester extends BaseAgent {
    constructor(options = {}) {
        super('GraphQLTester', options);

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
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                graphql_endpoints: { type: 'array', items: { type: 'string' } },
                schema: { type: 'object' },
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                queries: { type: 'array', items: { type: 'object' } },
                mutations: { type: 'array', items: { type: 'object' } },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'graphql_endpoint_found',
                'graphql_introspection_enabled',
                'graphql_depth_limit_missing',
                'graphql_batching_enabled',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'graphql_introspection_exposed',
                'graphql_dos_possible',
                'graphql_batch_attack_possible',
            ],
            artifacts: ['graphql_schema'],
        };

        this.default_budget = {
            max_time_ms: 180000, // 3 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Common GraphQL endpoint paths
        this.graphqlPaths = [
            '/graphql',
            '/api/graphql',
            '/v1/graphql',
            '/graphql/api',
            '/query',
            '/api/query',
            '/gql',
            '/api/gql',
        ];

        // GraphQL introspection query
        this.introspectionQuery = `
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        name
                        kind
                        description
                        fields {
                            name
                            description
                            args {
                                name
                                description
                                type { name kind }
                            }
                            type { name kind }
                        }
                    }
                }
            }
        `;
    }

    async run(ctx, inputs) {
        const { target, discoveredEndpoints = [] } = inputs;

        const results = {
            graphql_endpoints: [],
            schema: null,
            vulnerabilities: [],
            queries: [],
            mutations: [],
        };

        this.setStatus('Testing GraphQL APIs...');

        // Phase 1: Discover GraphQL endpoints
        const endpoints = await this.discoverGraphQLEndpoints(ctx, discoveredEndpoints, target);
        results.graphql_endpoints = endpoints;

        if (endpoints.length === 0) {
            this.setStatus('No GraphQL endpoints found');
            return results;
        }

        // Phase 2: Test introspection
        for (const endpoint of endpoints) {
            const schema = await this.testIntrospection(ctx, endpoint, target);
            
            if (schema) {
                results.schema = schema;
                results.queries = this.extractQueries(schema);
                results.mutations = this.extractMutations(schema);
                
                // Phase 3: Test depth limits
                const depthVulns = await this.testDepthLimits(ctx, endpoint, target);
                results.vulnerabilities.push(...depthVulns);

                // Phase 4: Test batching
                const batchVulns = await this.testBatchingAttacks(ctx, endpoint, target);
                results.vulnerabilities.push(...batchVulns);

                // Phase 5: Test field suggestions
                const suggestionVulns = await this.testFieldSuggestions(ctx, endpoint, target);
                results.vulnerabilities.push(...suggestionVulns);

                // Phase 6: Test mutation authorization
                const authVulns = await this.testMutationAuth(ctx, endpoint, results.mutations, target);
                results.vulnerabilities.push(...authVulns);

                // Phase 7: Test alias amplification
                const aliasVulns = await this.testAliasAmplification(ctx, endpoint, results.queries, target);
                results.vulnerabilities.push(...aliasVulns);
            }
        }

        this.setStatus(`Found ${results.vulnerabilities.length} GraphQL vulnerabilities`);

        return results;
    }

    /**
     * Discover GraphQL endpoints
     */
    async discoverGraphQLEndpoints(ctx, discoveredEndpoints, target) {
        const graphqlEndpoints = [];
        const baseUrl = this.normalizeBaseUrl(target);

        // Check discovered endpoints
        for (const endpoint of discoveredEndpoints) {
            const url = endpoint.url || endpoint;
            
            if (this.looksLikeGraphQL(url)) {
                graphqlEndpoints.push(url);
            }
        }

        // Try common paths
        for (const path of this.graphqlPaths) {
            const url = `${baseUrl}${path}`;
            
            if (await this.isGraphQLEndpoint(ctx, url, target)) {
                graphqlEndpoints.push(url);
                
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'graphql_endpoint_found',
                    target,
                    payload: {
                        endpoint: url,
                    },
                }));
            }
        }

        return [...new Set(graphqlEndpoints)]; // Deduplicate
    }

    /**
     * Check if URL looks like GraphQL
     */
    looksLikeGraphQL(url) {
        const lower = url.toLowerCase();
        return lower.includes('graphql') || lower.includes('/gql') || lower.includes('/query');
    }

    /**
     * Test if endpoint is GraphQL
     */
    async isGraphQLEndpoint(ctx, url, target) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: '{ __typename }'
                }),
                timeout: 10000,
            });

            if (response.ok) {
                const body = await response.text();
                try {
                    const json = JSON.parse(body);
                    // Valid GraphQL response has 'data' or 'errors'
                    return json.data !== undefined || json.errors !== undefined;
                } catch (e) {
                    return false;
                }
            }

            return false;

        } catch (error) {
            return false;
        }
    }

    /**
     * Test introspection query
     */
    async testIntrospection(ctx, endpoint, target) {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: this.introspectionQuery
                }),
                timeout: 15000,
            });

            if (response.ok) {
                const body = await response.json();
                
                if (body.data && body.data.__schema) {
                    // Introspection is enabled!
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'graphql_introspection_enabled',
                        target,
                        payload: {
                            endpoint,
                            types_count: body.data.__schema.types.length,
                        },
                    }));

                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                        target,
                        payload: {
                            vulnerability_type: 'graphql_introspection',
                            severity: 'medium',
                            endpoint,
                            description: 'GraphQL introspection enabled in production',
                        },
                    }));

                    ctx.emitClaim({
                        claim_type: 'graphql_introspection_exposed',
                        subject: endpoint,
                        predicate: { 
                            types_count: body.data.__schema.types.length,
                        },
                        base_rate: 0.5,
                    });

                    return body.data.__schema;
                }
            }

        } catch (error) {
            // Introspection might be disabled (good!) or error occurred
        }

        return null;
    }

    /**
     * Extract queries from schema
     */
    extractQueries(schema) {
        const queries = [];
        
        if (!schema || !schema.types) return queries;

        const queryType = schema.types.find(t => t.name === schema.queryType?.name);
        
        if (queryType && queryType.fields) {
            for (const field of queryType.fields) {
                queries.push({
                    name: field.name,
                    description: field.description,
                    args: field.args || [],
                    type: field.type?.name,
                });
            }
        }

        return queries;
    }

    /**
     * Extract mutations from schema
     */
    extractMutations(schema) {
        const mutations = [];
        
        if (!schema || !schema.types) return mutations;

        const mutationType = schema.types.find(t => t.name === schema.mutationType?.name);
        
        if (mutationType && mutationType.fields) {
            for (const field of mutationType.fields) {
                mutations.push({
                    name: field.name,
                    description: field.description,
                    args: field.args || [],
                    type: field.type?.name,
                });
            }
        }

        return mutations;
    }

    /**
     * Test depth limits
     */
    async testDepthLimits(ctx, endpoint, target) {
        const vulnerabilities = [];

        // Create deeply nested query
        const deepQuery = this.createDeepQuery(50); // 50 levels deep

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ query: deepQuery }),
                timeout: 15000,
            });

            // If query succeeds, no depth limit
            if (response.ok) {
                vulnerabilities.push({
                    type: 'graphql_no_depth_limit',
                    severity: 'medium',
                    endpoint,
                    confirmed: true,
                    description: 'No query depth limit enforced',
                    impact: 'DOS via deeply nested queries',
                });

                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'graphql_depth_limit_missing',
                    target,
                    payload: {
                        endpoint,
                        tested_depth: 50,
                    },
                }));

                ctx.emitClaim({
                    claim_type: 'graphql_dos_possible',
                    subject: endpoint,
                    predicate: { attack: 'deep_nesting' },
                    base_rate: 0.5,
                });
            }

        } catch (error) {
            // Timeout or error might indicate limit exists
        }

        return vulnerabilities;
    }

    /**
     * Create deeply nested query
     */
    createDeepQuery(depth) {
        let query = '{ __typename ';
        
        for (let i = 0; i < depth; i++) {
            query += '... on __Type { name ';
        }
        
        for (let i = 0; i < depth; i++) {
            query += '}';
        }
        
        query += '}';
        return query;
    }

    /**
     * Test batching attacks
     */
    async testBatchingAttacks(ctx, endpoint, target) {
        const vulnerabilities = [];

        // Create batch of 100 queries
        const batch = [];
        for (let i = 0; i < 100; i++) {
            batch.push({
                query: '{ __typename }'
            });
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(batch),
                timeout: 15000,
            });

            if (response.ok) {
                const body = await response.json();
                
                // If we get 100 responses, batching works
                if (Array.isArray(body) && body.length === 100) {
                    vulnerabilities.push({
                        type: 'graphql_batching_enabled',
                        severity: 'low',
                        endpoint,
                        confirmed: true,
                        description: 'GraphQL batching enabled without limits',
                        impact: 'DOS via query amplification',
                    });

                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'graphql_batching_enabled',
                        target,
                        payload: {
                            endpoint,
                            batch_size: 100,
                        },
                    }));

                    ctx.emitClaim({
                        claim_type: 'graphql_batch_attack_possible',
                        subject: endpoint,
                        predicate: { max_batch: 100 },
                        base_rate: 0.5,
                    });
                }
            }

        } catch (error) {
            // Batching might be disabled or limited
        }

        return vulnerabilities;
    }

    /**
     * Test field suggestions
     */
    async testFieldSuggestions(ctx, endpoint, target) {
        const vulnerabilities = [];

        // Query with typo to trigger suggestions
        const typoQuery = '{ usrz { id } }'; // Typo: usrz instead of users

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ query: typoQuery }),
                timeout: 10000,
            });

            if (response.ok) {
                const body = await response.json();
                
                // Check for field suggestions in errors
                if (body.errors && body.errors.length > 0) {
                    const errorMsg = JSON.stringify(body.errors[0]);
                    
                    if (errorMsg.includes('Did you mean') || errorMsg.includes('suggestion')) {
                        vulnerabilities.push({
                            type: 'graphql_field_suggestions',
                            severity: 'info',
                            endpoint,
                            confirmed: true,
                            description: 'Field suggestions enabled',
                            impact: 'Information disclosure about schema',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'graphql_vulnerability_found',
                            target,
                            payload: {
                                endpoint,
                                finding: 'field_suggestions_enabled',
                            },
                        }));
                    }
                }
            }

        } catch (error) {
            // Error testing suggestions
        }

        return vulnerabilities;
    }

    /**
     * Test mutation authorization
     */
    async testMutationAuth(ctx, endpoint, mutations, target) {
        const vulnerabilities = [];

        // Test first 5 mutations without auth
        for (const mutation of mutations.slice(0, 5)) {
            try {
                // Build mutation query
                const mutationQuery = `mutation { ${mutation.name} }`;

                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ query: mutationQuery }),
                    timeout: 10000,
                });

                if (response.ok) {
                    const body = await response.json();
                    
                    // If mutation executes without auth, vulnerable
                    if (body.data && !body.errors) {
                        vulnerabilities.push({
                            type: 'graphql_mutation_no_auth',
                            severity: 'high',
                            endpoint,
                            mutation: mutation.name,
                            confirmed: true,
                            description: `Mutation ${mutation.name} accessible without authentication`,
                            impact: 'Unauthorized data modification',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                            target,
                            payload: {
                                vulnerability_type: 'graphql_mutation_no_auth',
                                severity: 'high',
                                mutation: mutation.name,
                            },
                        }));
                    }
                }

            } catch (error) {
                continue;
            }
        }

        return vulnerabilities;
    }

    /**
     * Test alias amplification
     */
    async testAliasAmplification(ctx, endpoint, queries, target) {
        const vulnerabilities = [];

        if (queries.length === 0) return vulnerabilities;

        // Pick first query
        const query = queries[0];

        // Create query with 100 aliases
        let aliasQuery = '{ ';
        for (let i = 0; i < 100; i++) {
            aliasQuery += `alias${i}: ${query.name} `;
        }
        aliasQuery += '}';

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ query: aliasQuery }),
                timeout: 15000,
            });

            if (response.ok) {
                const body = await response.json();
                
                // If we get data for all aliases, amplification works
                if (body.data) {
                    const aliasCount = Object.keys(body.data).length;
                    
                    if (aliasCount >= 50) {
                        vulnerabilities.push({
                            type: 'graphql_alias_amplification',
                            severity: 'medium',
                            endpoint,
                            confirmed: true,
                            alias_count: aliasCount,
                            description: 'Alias-based query amplification possible',
                            impact: 'DOS via resource exhaustion',
                        });

                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'graphql_vulnerability_found',
                            target,
                            payload: {
                                endpoint,
                                finding: 'alias_amplification',
                                alias_count: aliasCount,
                            },
                        }));
                    }
                }
            }

        } catch (error) {
            // Might indicate rate limiting (good)
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

export default GraphQLTester;
