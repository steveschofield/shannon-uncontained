/**
 * APISchemaGenerator - Automatic API schema inference agent
 * 
 * Learns API structure from HTTP traffic without needing OpenAPI specs.
 * Generates comprehensive API documentation automatically by analyzing:
 * - Endpoint patterns and relationships
 * - Parameter types and constraints
 * - Request/response formats
 * - CRUD operation inference
 * - Data model relationships
 * 
 * WHY THIS IS CRITICAL FOR BLACKBOX:
 * - 90% of APIs have no documentation
 * - Enables systematic testing without specs
 * - Discovers hidden endpoints via pattern inference
 * - Feeds all other vulnerability agents
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';

export class APISchemaGenerator extends BaseAgent {
    constructor(options = {}) {
        super('APISchemaGenerator', options);

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
                responses: {
                    type: 'array',
                    description: 'HTTP responses to analyze',
                    items: { type: 'object' }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                api_schema: { type: 'object' },
                endpoints: { type: 'array', items: { type: 'object' } },
                resources: { type: 'array', items: { type: 'object' } },
                inferred_endpoints: { type: 'array', items: { type: 'string' } },
                data_models: { type: 'object' },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'api_endpoint_inferred',
                'api_resource_discovered',
                'api_pattern_detected',
                'data_model_inferred',
            ],
            model_updates: [],
            claims: [
                'rest_api_detected',
                'crud_operations_available',
                'api_version_detected',
            ],
            artifacts: ['openapi_schema'],
        };

        this.default_budget = {
            max_time_ms: 180000, // 3 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Common API path patterns
        this.apiPatterns = [
            /\/api\//i,
            /\/v\d+\//,
            /\/rest\//i,
            /\/graphql/i,
            /\/services\//i,
        ];

        // HTTP methods by operation type
        this.crudMapping = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete',
        };

        // Common resource patterns
        this.resourcePatterns = {
            collection: /\/([a-z]+)s?$/i,  // /users, /products
            item: /\/([a-z]+)s?\/(\d+|[a-f0-9-]+)$/i,  // /users/123
            nested: /\/([a-z]+)s?\/(\d+|[a-f0-9-]+)\/([a-z]+)s?$/i,  // /users/123/orders
        };
    }

    async run(ctx, inputs) {
        const { target, discoveredEndpoints = [], responses = [] } = inputs;

        const results = {
            api_schema: {
                openapi: '3.0.0',
                info: {
                    title: `API Schema for ${target}`,
                    version: '1.0.0',
                    description: 'Auto-generated schema by Shannon APISchemaGenerator',
                },
                servers: [{ url: this.normalizeBaseUrl(target) }],
                paths: {},
            },
            endpoints: [],
            resources: [],
            inferred_endpoints: [],
            data_models: {},
        };

        this.setStatus('Analyzing API structure...');

        // Phase 1: Identify API endpoints
        const apiEndpoints = this.identifyAPIEndpoints(discoveredEndpoints);
        
        // Phase 2: Analyze endpoint patterns
        const patterns = this.analyzeEndpointPatterns(apiEndpoints);
        
        // Phase 3: Infer resources and operations
        const resources = this.inferResources(patterns);
        results.resources = resources;

        // Phase 4: Infer additional endpoints
        const inferredEndpoints = await this.inferAdditionalEndpoints(
            ctx,
            resources,
            target
        );
        results.inferred_endpoints = inferredEndpoints;

        // Phase 5: Analyze responses to build data models
        if (responses.length > 0) {
            const models = this.buildDataModels(responses);
            results.data_models = models;
        }

        // Phase 6: Generate OpenAPI schema
        const schema = this.generateOpenAPISchema(
            resources,
            results.data_models,
            target
        );
        results.api_schema = schema;
        results.endpoints = resources;

        // Emit evidence
        ctx.emitEvidence(createEvidenceEvent({
            source: this.name,
            event_type: 'api_pattern_detected',
            target,
            payload: {
                total_endpoints: apiEndpoints.length,
                resources: resources.length,
                inferred_endpoints: inferredEndpoints.length,
            },
        }));

        ctx.emitClaim({
            claim_type: 'rest_api_detected',
            subject: target,
            predicate: { endpoints: apiEndpoints.length },
            base_rate: 0.5,
        });

        this.setStatus(`Generated schema with ${resources.length} resources`);

        return results;
    }

    /**
     * Identify which endpoints are API endpoints
     */
    identifyAPIEndpoints(endpoints) {
        const apiEndpoints = [];

        for (const endpoint of endpoints) {
            const url = endpoint.url || endpoint;
            
            // Check if URL matches API patterns
            if (this.isAPIEndpoint(url)) {
                apiEndpoints.push({
                    url,
                    method: endpoint.method || 'GET',
                    ...endpoint,
                });
            }
        }

        return apiEndpoints;
    }

    /**
     * Check if URL is an API endpoint
     */
    isAPIEndpoint(url) {
        try {
            const parsed = new URL(url);
            const path = parsed.pathname;

            // Check common API patterns
            for (const pattern of this.apiPatterns) {
                if (pattern.test(path)) {
                    return true;
                }
            }

            // Check for JSON response indicators
            if (path.includes('.json')) {
                return true;
            }

            return false;

        } catch (error) {
            return false;
        }
    }

    /**
     * Analyze patterns in API endpoints
     */
    analyzeEndpointPatterns(endpoints) {
        const patterns = {
            basePaths: new Set(),
            versions: new Set(),
            collections: {},
            items: {},
            nested: {},
        };

        for (const endpoint of endpoints) {
            const url = endpoint.url;
            
            try {
                const parsed = new URL(url);
                const path = parsed.pathname;

                // Extract base path (e.g., /api or /rest)
                const baseMatch = path.match(/^\/(?:api|rest|v\d+)/i);
                if (baseMatch) {
                    patterns.basePaths.add(baseMatch[0]);
                }

                // Extract version
                const versionMatch = path.match(/\/v(\d+)\//);
                if (versionMatch) {
                    patterns.versions.add(versionMatch[1]);
                }

                // Match resource patterns
                this.matchResourcePattern(path, endpoint, patterns);

            } catch (error) {
                continue;
            }
        }

        return patterns;
    }

    /**
     * Match endpoint to resource patterns
     */
    matchResourcePattern(path, endpoint, patterns) {
        // Collection: /api/users
        const collectionMatch = path.match(this.resourcePatterns.collection);
        if (collectionMatch) {
            const resource = collectionMatch[1];
            if (!patterns.collections[resource]) {
                patterns.collections[resource] = [];
            }
            patterns.collections[resource].push(endpoint);
            return;
        }

        // Item: /api/users/123
        const itemMatch = path.match(this.resourcePatterns.item);
        if (itemMatch) {
            const resource = itemMatch[1];
            const id = itemMatch[2];
            if (!patterns.items[resource]) {
                patterns.items[resource] = [];
            }
            patterns.items[resource].push({
                ...endpoint,
                id_example: id,
                id_type: /^\d+$/.test(id) ? 'integer' : 'uuid',
            });
            return;
        }

        // Nested: /api/users/123/orders
        const nestedMatch = path.match(this.resourcePatterns.nested);
        if (nestedMatch) {
            const parentResource = nestedMatch[1];
            const parentId = nestedMatch[2];
            const childResource = nestedMatch[3];
            
            const key = `${parentResource}/${childResource}`;
            if (!patterns.nested[key]) {
                patterns.nested[key] = [];
            }
            patterns.nested[key].push({
                ...endpoint,
                parent_resource: parentResource,
                parent_id: parentId,
                child_resource: childResource,
            });
        }
    }

    /**
     * Infer resources from patterns
     */
    inferResources(patterns) {
        const resources = [];

        // Process collections
        for (const [resourceName, endpoints] of Object.entries(patterns.collections)) {
            const resource = {
                name: resourceName,
                type: 'collection',
                endpoints: endpoints.map(e => ({
                    path: new URL(e.url).pathname,
                    method: e.method || 'GET',
                    operation: this.crudMapping[e.method] || 'unknown',
                })),
                operations: this.inferOperations(endpoints),
            };
            resources.push(resource);
        }

        // Process items
        for (const [resourceName, endpoints] of Object.entries(patterns.items)) {
            const existing = resources.find(r => r.name === resourceName);
            
            if (existing) {
                // Add item operations to existing resource
                existing.endpoints.push(...endpoints.map(e => ({
                    path: new URL(e.url).pathname,
                    method: e.method || 'GET',
                    operation: this.crudMapping[e.method] || 'unknown',
                    has_id: true,
                    id_type: e.id_type,
                })));
            } else {
                // Create new resource
                resources.push({
                    name: resourceName,
                    type: 'item',
                    endpoints: endpoints.map(e => ({
                        path: new URL(e.url).pathname,
                        method: e.method || 'GET',
                        operation: this.crudMapping[e.method] || 'unknown',
                        has_id: true,
                        id_type: e.id_type,
                    })),
                    operations: this.inferOperations(endpoints),
                });
            }
        }

        // Process nested resources
        for (const [key, endpoints] of Object.entries(patterns.nested)) {
            resources.push({
                name: key,
                type: 'nested',
                endpoints: endpoints.map(e => ({
                    path: new URL(e.url).pathname,
                    method: e.method || 'GET',
                    operation: this.crudMapping[e.method] || 'unknown',
                    parent: e.parent_resource,
                    child: e.child_resource,
                })),
                operations: this.inferOperations(endpoints),
            });
        }

        return resources;
    }

    /**
     * Infer available operations for resource
     */
    inferOperations(endpoints) {
        const operations = new Set();
        
        for (const endpoint of endpoints) {
            const method = endpoint.method || 'GET';
            const operation = this.crudMapping[method];
            if (operation) {
                operations.add(operation);
            }
        }

        return Array.from(operations);
    }

    /**
     * Infer additional endpoints based on patterns
     */
    async inferAdditionalEndpoints(ctx, resources, target) {
        const inferred = [];
        const baseUrl = this.normalizeBaseUrl(target);

        for (const resource of resources) {
            if (resource.type === 'collection') {
                const basePath = this.extractBasePath(resource.endpoints[0].path);
                
                // If we have collection, infer item endpoint
                if (!resource.operations.includes('read')) {
                    const itemPath = `${basePath}/{id}`;
                    inferred.push(itemPath);
                    
                    ctx.emitEvidence(createEvidenceEvent({
                        source: this.name,
                        event_type: 'api_endpoint_inferred',
                        target,
                        payload: {
                            inferred_path: itemPath,
                            resource: resource.name,
                            method: 'GET',
                        },
                    }));
                }

                // Infer CRUD operations
                const possibleOperations = [
                    { method: 'POST', path: basePath, operation: 'create' },
                    { method: 'PUT', path: `${basePath}/{id}`, operation: 'update' },
                    { method: 'DELETE', path: `${basePath}/{id}`, operation: 'delete' },
                ];

                for (const op of possibleOperations) {
                    if (!resource.operations.includes(op.operation)) {
                        inferred.push(`${op.method} ${op.path}`);
                        
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'api_endpoint_inferred',
                            target,
                            payload: {
                                inferred_path: op.path,
                                method: op.method,
                                operation: op.operation,
                                resource: resource.name,
                            },
                        }));
                    }
                }
            }
        }

        return inferred;
    }

    /**
     * Build data models from responses
     */
    buildDataModels(responses) {
        const models = {};

        for (const response of responses) {
            const { url, body } = response;

            if (!body) continue;

            try {
                const json = JSON.parse(body);
                const resourceName = this.extractResourceName(url);

                if (!resourceName) continue;

                // Analyze JSON structure
                const schema = this.inferJSONSchema(json);
                
                if (!models[resourceName]) {
                    models[resourceName] = {
                        examples: [],
                        schema,
                    };
                } else {
                    // Merge schemas
                    models[resourceName].schema = this.mergeSchemas(
                        models[resourceName].schema,
                        schema
                    );
                }

                models[resourceName].examples.push(json);

            } catch (error) {
                // Not JSON, skip
                continue;
            }
        }

        return models;
    }

    /**
     * Infer JSON schema from object
     */
    inferJSONSchema(obj) {
        if (Array.isArray(obj)) {
            if (obj.length > 0) {
                return {
                    type: 'array',
                    items: this.inferJSONSchema(obj[0]),
                };
            }
            return { type: 'array' };
        }

        if (typeof obj === 'object' && obj !== null) {
            const properties = {};
            const required = [];

            for (const [key, value] of Object.entries(obj)) {
                properties[key] = this.inferJSONSchema(value);
                required.push(key);
            }

            return {
                type: 'object',
                properties,
                required,
            };
        }

        // Primitive types
        if (typeof obj === 'string') return { type: 'string' };
        if (typeof obj === 'number') {
            return Number.isInteger(obj) ? { type: 'integer' } : { type: 'number' };
        }
        if (typeof obj === 'boolean') return { type: 'boolean' };
        if (obj === null) return { type: 'null' };

        return { type: 'string' }; // fallback
    }

    /**
     * Merge two schemas
     */
    mergeSchemas(schema1, schema2) {
        if (schema1.type !== schema2.type) {
            return schema1; // Keep first one if types differ
        }

        if (schema1.type === 'object') {
            const merged = {
                type: 'object',
                properties: { ...schema1.properties, ...schema2.properties },
                required: Array.from(new Set([
                    ...(schema1.required || []),
                    ...(schema2.required || []),
                ])),
            };
            return merged;
        }

        return schema1;
    }

    /**
     * Generate OpenAPI schema
     */
    generateOpenAPISchema(resources, dataModels, target) {
        const schema = {
            openapi: '3.0.0',
            info: {
                title: `API Schema for ${target}`,
                version: '1.0.0',
                description: 'Auto-generated by Shannon APISchemaGenerator',
            },
            servers: [{ url: this.normalizeBaseUrl(target) }],
            paths: {},
            components: {
                schemas: dataModels,
            },
        };

        // Build paths from resources
        for (const resource of resources) {
            for (const endpoint of resource.endpoints) {
                const path = endpoint.path.replace(/\/\d+/g, '/{id}');
                const method = endpoint.method.toLowerCase();

                if (!schema.paths[path]) {
                    schema.paths[path] = {};
                }

                schema.paths[path][method] = {
                    summary: `${endpoint.operation} ${resource.name}`,
                    operationId: `${endpoint.operation}${resource.name}`,
                    responses: {
                        '200': {
                            description: 'Successful response',
                        },
                    },
                };

                // Add parameters for paths with IDs
                if (path.includes('{id}')) {
                    schema.paths[path][method].parameters = [
                        {
                            name: 'id',
                            in: 'path',
                            required: true,
                            schema: {
                                type: endpoint.id_type === 'integer' ? 'integer' : 'string',
                            },
                        },
                    ];
                }
            }
        }

        return schema;
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

    extractBasePath(path) {
        // Remove ID segments
        return path.replace(/\/\d+$/, '').replace(/\/[a-f0-9-]{8,}$/i, '');
    }

    extractResourceName(url) {
        try {
            const parsed = new URL(url);
            const match = parsed.pathname.match(/\/([a-z]+)(?:s)?(?:\/|$)/i);
            return match ? match[1] : null;
        } catch {
            return null;
        }
    }
}

export default APISchemaGenerator;
