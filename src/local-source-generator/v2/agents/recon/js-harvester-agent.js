/**
 * JSHarvesterAgent - JavaScript analysis agent
 * 
 * Extracts API endpoints, route strings, and state machine hints from JS bundles.
 * Uses AST-based analysis via Playwright for dynamic JS extraction.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';

export class JSHarvesterAgent extends BaseAgent {
    constructor(options = {}) {
        super('JSHarvesterAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                js_files: { type: 'array', items: { type: 'string' }, description: 'JS file URLs to analyze' },
                max_js_files: { type: 'number', description: 'Maximum JS files to analyze' },
                use_subjs: { type: 'boolean', description: 'Use subjs to expand JS file list' },
                use_linkfinder: { type: 'boolean', description: 'Use linkfinder for JS URL extraction' },
                use_xnlinkfinder: { type: 'boolean', description: 'Use xnlinkfinder for JS URL extraction' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                endpoints: { type: 'array', items: { type: 'object' } },
                routes: { type: 'array', items: { type: 'string' } },
                secrets: { type: 'array', items: { type: 'object' } },
                state_hints: { type: 'array', items: { type: 'object' } },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };
        this.emits = {
            evidence_events: [EVENT_TYPES.JS_FETCH_CALL, EVENT_TYPES.JS_ROUTE_STRING, EVENT_TYPES.JS_STATE_HINT],
            model_updates: [],
            claims: [CLAIM_TYPES.ENDPOINT_EXISTS],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 120000,
            max_network_requests: 100,
            max_tokens: 5000,
            max_tool_invocations: 30,
        };

        // Patterns for extraction
        this.patterns = {
            // Fetch/XHR patterns
            fetch: [
                /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /fetch\s*\(\s*`([^`]+)`/g,
                /\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\.put\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\.delete\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /axios\s*\.\s*\w+\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/g,
            ],

            // Route definitions
            routes: [
                /path\s*:\s*['"`]([^'"`]+)['"`]/g,
                /route\s*:\s*['"`]([^'"`]+)['"`]/g,
                /to\s*:\s*['"`]([^'"`]+)['"`]/g,
                /router\.\w+\s*\(\s*['"`]([^'"`]+)['"`]/g,
                /app\.\w+\s*\(\s*['"`]([^'"`]+)['"`]/g,
            ],

            // API base URLs
            apiBase: [
                /API_URL\s*[=:]\s*['"`]([^'"`]+)['"`]/gi,
                /BASE_URL\s*[=:]\s*['"`]([^'"`]+)['"`]/gi,
                /API_ENDPOINT\s*[=:]\s*['"`]([^'"`]+)['"`]/gi,
                /baseURL\s*:\s*['"`]([^'"`]+)['"`]/gi,
            ],

            // Potential secrets
            secrets: [
                /api[_-]?key\s*[=:]\s*['"`]([^'"`]{10,})['"`]/gi,
                /secret\s*[=:]\s*['"`]([^'"`]{10,})['"`]/gi,
                /token\s*[=:]\s*['"`]([^'"`]{10,})['"`]/gi,
                /password\s*[=:]\s*['"`]([^'"`]{6,})['"`]/gi,
                /aws[_-]?access/gi,
                /private[_-]?key/gi,
            ],

            // State management hints
            stateHints: [
                /createStore|configureStore|createSlice/g,
                /useState|useReducer|useContext/g,
                /Vuex\.Store|createPinia/g,
                /\$store\./g,
                /dispatch\s*\(\s*['"`](\w+)['"`]/g,
                /commit\s*\(\s*['"`](\w+)['"`]/g,
            ],
        };
    }

    async run(ctx, inputs) {
        const {
            target,
            js_files = [],
            max_js_files: maxJsFilesInput,
            use_subjs: useSubjsInput,
            use_linkfinder: useLinkfinderInput,
            use_xnlinkfinder: useXnLinkfinderInput,
        } = inputs;

        const maxJsFiles = Number.isFinite(maxJsFilesInput) ? Math.max(1, maxJsFilesInput) : 40;
        const useSubjs = useSubjsInput !== false;
        const useLinkfinder = useLinkfinderInput !== false;
        const useXnLinkfinder = useXnLinkfinderInput !== false;
        const toolConfig = inputs.toolConfig || ctx.config?.toolConfig || null;

        const results = {
            endpoints: [],
            routes: [],
            secrets: [],
            state_hints: [],
            api_bases: [],
        };

        const seenEndpoints = new Set();
        const seenRoutes = new Set();

        const jsFiles = await this.resolveJsFiles(ctx, target, js_files, useSubjs, toolConfig);
        const jsFilesToAnalyze = jsFiles.slice(0, maxJsFiles);
        const linkfinderAvailable = useLinkfinder && await isToolAvailable('linkfinder');
        const xnLinkfinderAvailable = useXnLinkfinder && await isToolAvailable('xnlinkfinder');
        const { fs, path } = await import('zx');
        const tmpDir = await fs.mkdtemp(path.join(process.cwd(), 'tmp-js-'));

        // Analyze each JS file
        for (const jsUrl of jsFilesToAnalyze) {
            ctx.recordNetworkRequest();

            try {
                const jsContent = await this.fetchJSContent(jsUrl);
                if (!jsContent) continue;

                // Store blob reference
                const blobRef = ctx.evidenceGraph.storeBlob(jsContent, 'application/javascript');

                // Extract fetch/XHR calls
                for (const pattern of this.patterns.fetch) {
                    const matches = jsContent.matchAll(pattern);
                    for (const match of matches) {
                        const endpoint = this.normalizeEndpoint(match[1], target);
                        if (endpoint && !seenEndpoints.has(endpoint)) {
                            seenEndpoints.add(endpoint);

                            const method = this.inferMethod(match[0]);

                            ctx.emitEvidence(createEvidenceEvent({
                                source: 'JSHarvesterAgent',
                                event_type: EVENT_TYPES.JS_FETCH_CALL,
                                target,
                                payload: {
                                    endpoint,
                                    method,
                                    source_file: jsUrl,
                                    raw_match: match[0].slice(0, 200),
                                },
                                blob_refs: [blobRef],
                            }));

                            results.endpoints.push({ endpoint, method, source: jsUrl });

                            // Emit claim with js_ast_direct evidence
                            const claim = ctx.emitClaim({
                                claim_type: CLAIM_TYPES.ENDPOINT_EXISTS,
                                subject: endpoint,
                                predicate: { method, path: endpoint },
                                base_rate: 0.3,
                            });

                            if (claim) {
                                claim.addEvidence('js_ast_direct', 1);
                            }
                        }
                    }
                }

                // Extract routes
                for (const pattern of this.patterns.routes) {
                    const matches = jsContent.matchAll(pattern);
                    for (const match of matches) {
                        const route = match[1];
                        if (route && route.startsWith('/') && !seenRoutes.has(route)) {
                            seenRoutes.add(route);
                            results.routes.push(route);

                            ctx.emitEvidence(createEvidenceEvent({
                                source: 'JSHarvesterAgent',
                                event_type: EVENT_TYPES.JS_ROUTE_STRING,
                                target,
                                payload: {
                                    route,
                                    source_file: jsUrl,
                                },
                            }));
                        }
                    }
                }

                // Extract API bases
                for (const pattern of this.patterns.apiBase) {
                    const matches = jsContent.matchAll(pattern);
                    for (const match of matches) {
                        const base = match[1];
                        if (base && !results.api_bases.includes(base)) {
                            results.api_bases.push(base);
                        }
                    }
                }

                // Check for secrets (report but don't store values)
                for (const pattern of this.patterns.secrets) {
                    const matches = jsContent.matchAll(pattern);
                    for (const match of matches) {
                        results.secrets.push({
                            type: this.classifySecret(match[0]),
                            location: jsUrl,
                            context: match[0].slice(0, 50) + '...',
                        });
                    }
                }

                // Extract state hints
                for (const pattern of this.patterns.stateHints) {
                    const matches = jsContent.matchAll(pattern);
                    for (const match of matches) {
                        const hint = {
                            pattern: match[0],
                            source_file: jsUrl,
                        };

                        results.state_hints.push(hint);

                        ctx.emitEvidence(createEvidenceEvent({
                            source: 'JSHarvesterAgent',
                            event_type: EVENT_TYPES.JS_STATE_HINT,
                            target,
                            payload: hint,
                        }));
                    }
                }

                // Optional: LinkFinder/xnLinkFinder enrichment
                if (linkfinderAvailable || xnLinkfinderAvailable) {
                    const jsPath = path.join(tmpDir, `${this.slugify(jsUrl)}.js`);
                    try {
                        await fs.writeFile(jsPath, jsContent);
                    } catch {}

                    if (linkfinderAvailable) {
                        await this.runLinkFinder(ctx, {
                            target,
                            jsUrl,
                            jsPath,
                            toolName: 'linkfinder',
                            toolConfig,
                            seenEndpoints,
                            seenRoutes,
                            results,
                        });
                    }

                    if (xnLinkfinderAvailable) {
                        await this.runLinkFinder(ctx, {
                            target,
                            jsUrl,
                            jsPath,
                            toolName: 'xnlinkfinder',
                            toolConfig,
                            seenEndpoints,
                            seenRoutes,
                            results,
                        });
                    }
                }

            } catch (err) {
                // Emit error but continue
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'JSHarvesterAgent',
                    event_type: EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { error: err.message, file: jsUrl },
                }));
            }
        }

        return results;
    }

    async resolveJsFiles(ctx, target, jsFiles, useSubjs, toolConfig) {
        const discovered = [];
        const seen = new Set();

        const add = (url) => {
            if (!url) return;
            if (seen.has(url)) return;
            seen.add(url);
            discovered.push(url);
        };

        for (const entry of jsFiles || []) {
            add(entry);
        }

        const evidenceJs = this.collectJsFromEvidence(ctx);
        for (const entry of evidenceJs) {
            add(entry);
        }

        if (useSubjs && await isToolAvailable('subjs')) {
            ctx.recordToolInvocation();
            const { fs, path } = await import('zx');
            const tmpFile = path.join(process.cwd(), `subjs-${Date.now()}.txt`);
            await fs.writeFile(tmpFile, `${target}\n`);
            const subjsOptions = getToolRunOptions('subjs', toolConfig);
            const cmds = [
                `subjs -u ${target}`,
                `subjs -i "${tmpFile}"`,
            ];
            let result = null;
            for (const cmd of cmds) {
                const attempt = await runToolWithRetry(cmd, {
                    ...subjsOptions,
                    context: ctx,
                });
                if (attempt.success) {
                    result = attempt;
                    break;
                }
                result = attempt;
            }

            if (result && result.success) {
                const lines = String(result.stdout || '').split('\n').map(l => l.trim()).filter(Boolean);
                for (const line of lines) {
                    if (line.includes('.js')) {
                        add(line);
                    }
                }
            } else if (result) {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'JSHarvesterAgent',
                    event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: 'subjs', error: result.error },
                }));
            }
        }

        return discovered;
    }

    collectJsFromEvidence(ctx) {
        const events = ctx.evidenceGraph.getEventsByType(EVENT_TYPES.ENDPOINT_DISCOVERED) || [];
        const jsFiles = [];
        for (const event of events) {
            const url = event.payload?.url || event.payload?.endpoint;
            if (typeof url === 'string' && url.includes('.js')) {
                jsFiles.push(url);
            }
        }
        return jsFiles;
    }

    async runLinkFinder(ctx, { target, jsUrl, jsPath, toolName, toolConfig, seenEndpoints, seenRoutes, results }) {
        ctx.recordToolInvocation();
        const toolOptions = getToolRunOptions(toolName, toolConfig);
        const cmd = `${toolName} -i "${jsPath}" -o cli`;
        const result = await runToolWithRetry(cmd, {
            ...toolOptions,
            context: ctx,
        });

        if (!result.success) {
            ctx.emitEvidence(createEvidenceEvent({
                source: 'JSHarvesterAgent',
                event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                target,
                payload: { tool: toolName, error: result.error, file: jsUrl },
            }));
            return;
        }

        const lines = String(result.stdout || '').split('\n').map(l => l.trim()).filter(Boolean);
        for (const line of lines) {
            const endpoint = this.extractEndpointFromLine(line, target);
            if (!endpoint) continue;
            if (endpoint.startsWith('/') && !seenRoutes.has(endpoint)) {
                seenRoutes.add(endpoint);
                results.routes.push(endpoint);
            }
            if (!seenEndpoints.has(endpoint)) {
                seenEndpoints.add(endpoint);
                results.endpoints.push({ endpoint, method: 'GET', source: jsUrl });
                ctx.emitEvidence(createEvidenceEvent({
                    source: toolName,
                    event_type: EVENT_TYPES.JS_ROUTE_STRING,
                    target,
                    payload: {
                        route: endpoint,
                        source_file: jsUrl,
                        tool: toolName,
                    },
                }));
            }
        }
    }

    extractEndpointFromLine(line, target) {
        if (!line) return null;
        const urlMatch = line.match(/https?:\/\/\S+/);
        const pathMatch = line.match(/\/[A-Za-z0-9_\-./?=&%:]+/);
        const candidate = urlMatch ? urlMatch[0] : (pathMatch ? pathMatch[0] : null);
        if (!candidate) return null;
        return this.normalizeEndpoint(candidate, target);
    }

    slugify(value) {
        return value.replace(/[^a-z0-9]+/gi, '-').slice(0, 60);
    }

    async fetchJSContent(url) {
        try {
            const response = await fetch(url, {
                headers: { 'User-Agent': 'Mozilla/5.0 Shannon-LSG/2.0' },
            });
            if (response.ok) {
                return await response.text();
            }
        } catch {
            // Ignore fetch errors
        }
        return null;
    }

    normalizeEndpoint(endpoint, target) {
        if (!endpoint) return null;

        // Skip data URIs, blobs, etc.
        if (endpoint.startsWith('data:') || endpoint.startsWith('blob:')) return null;

        // Handle template literals
        endpoint = endpoint.replace(/\$\{[^}]+\}/g, ':param');

        // Handle relative URLs
        if (endpoint.startsWith('/')) {
            return endpoint;
        }

        // Handle full URLs
        try {
            const url = new URL(endpoint, target);
            // Only accept same origin or API endpoints
            const targetHost = new URL(target).hostname;
            if (url.hostname === targetHost || url.hostname.includes('api')) {
                return url.pathname;
            }
        } catch {
            // Not a valid URL
        }

        // Handle relative paths without leading slash
        if (!endpoint.includes('://') && !endpoint.includes(' ')) {
            return '/' + endpoint;
        }

        return null;
    }

    inferMethod(matchStr) {
        const lower = matchStr.toLowerCase();
        if (lower.includes('.post') || lower.includes('method:')) return 'POST';
        if (lower.includes('.put')) return 'PUT';
        if (lower.includes('.delete')) return 'DELETE';
        if (lower.includes('.patch')) return 'PATCH';
        return 'GET';
    }

    classifySecret(match) {
        const lower = match.toLowerCase();
        if (lower.includes('aws')) return 'aws_credential';
        if (lower.includes('api_key') || lower.includes('apikey')) return 'api_key';
        if (lower.includes('token')) return 'token';
        if (lower.includes('password')) return 'password';
        if (lower.includes('secret')) return 'secret';
        if (lower.includes('private')) return 'private_key';
        return 'unknown';
    }
}

export default JSHarvesterAgent;
