/**
 * CrawlerAgent - Active crawling agent
 * 
 * Discovers endpoints, parameters, and forms via active crawling.
 * Uses katana and gau for discovery.
 */

import { BaseAgent } from '../base-agent.js';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';
import { normalizeKatana, normalizeGau, normalizeGauplus, normalizeGoSpider, normalizeHakrawler, normalizeWaybackUrls, normalizeWaymore } from '../../tools/normalizers/evidence-normalizers.js';
import { EVENT_TYPES, createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class CrawlerAgent extends BaseAgent {
    constructor(options = {}) {
        super('CrawlerAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                depth: { type: 'number', description: 'Crawl depth (default: 3)' },
                includeHistorical: { type: 'boolean', description: 'Include historical URLs from gau' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                endpoints: { type: 'array', items: { type: 'object' } },
                forms: { type: 'array', items: { type: 'object' } },
                js_files: { type: 'array', items: { type: 'string' } },
            },
        };

        this.requires = { evidence_kinds: [], model_nodes: [] };
        this.emits = {
            evidence_events: [EVENT_TYPES.ENDPOINT_DISCOVERED, EVENT_TYPES.FORM_DISCOVERED, EVENT_TYPES.LINK_DISCOVERED],
            model_updates: [],
            claims: [],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 300000,
            max_network_requests: 5000,
            max_tokens: 0,
            max_tool_invocations: 10,
        };
    }

    async run(ctx, inputs) {
        const { target, depth = 3, includeHistorical = true } = inputs;
        const hostname = this.extractHostname(target);

        const results = {
            endpoints: [],
            forms: [],
            js_files: [],
            sources: [],
        };

        const seenPaths = new Set();

        // Run katana for active crawling
        const katanaAvailable = await isToolAvailable('katana');
        if (katanaAvailable) {
            ctx.recordToolInvocation();

            const katanaCmd = `katana -u ${target} -d ${depth} -jc -silent -jsonl`;
            const katanaOptions = getToolRunOptions('katana', inputs.toolConfig);
            const katanaResult = await runToolWithRetry(katanaCmd, {
                ...katanaOptions,
                context: ctx,
            });

            if (katanaResult.success) {
                const events = normalizeKatana(katanaResult.stdout, target);
                results.sources.push('katana');

                for (const event of events) {
                    const path = event.payload.path;

                    if (!seenPaths.has(path)) {
                        seenPaths.add(path);
                        ctx.emitEvidence(event);

                        if (event.event_type === EVENT_TYPES.ENDPOINT_DISCOVERED) {
                            results.endpoints.push(event.payload);

                            // Track JS files
                            if (path.endsWith('.js')) {
                                results.js_files.push(event.payload.url);
                            }
                        }

                        if (event.event_type === EVENT_TYPES.FORM_DISCOVERED) {
                            results.forms.push(event.payload);
                        }
                    }
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'CrawlerAgent',
                    event_type: katanaResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: 'katana', error: katanaResult.error },
                }));
            }
        }

        const gospiderAvailable = await isToolAvailable('gospider');
        if (gospiderAvailable) {
            ctx.recordToolInvocation();

            const gospiderCmd = `gospider -s ${target} -d ${depth}`;
            const gospiderOptions = getToolRunOptions('gospider', inputs.toolConfig);
            const gospiderResult = await runToolWithRetry(gospiderCmd, {
                ...gospiderOptions,
                context: ctx,
            });

            if (gospiderResult.success) {
                const events = normalizeGoSpider(gospiderResult.stdout, target);
                results.sources.push('gospider');

                for (const event of events) {
                    const path = event.payload.path;

                    if (!seenPaths.has(path)) {
                        seenPaths.add(path);
                        ctx.emitEvidence(event);
                        results.endpoints.push(event.payload);

                        if (path.endsWith('.js')) {
                            results.js_files.push(event.payload.url);
                        }
                    }
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'CrawlerAgent',
                    event_type: gospiderResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: 'gospider', error: gospiderResult.error },
                }));
            }
        }

        const hakrawlerAvailable = await isToolAvailable('hakrawler');
        if (hakrawlerAvailable) {
            ctx.recordToolInvocation();

            const hakrawlerCmd = `printf "%s\\n" "${target}" | hakrawler -plain -depth ${depth}`;
            const hakrawlerOptions = getToolRunOptions('hakrawler', inputs.toolConfig);
            const hakrawlerResult = await runToolWithRetry(hakrawlerCmd, {
                ...hakrawlerOptions,
                context: ctx,
            });

            if (hakrawlerResult.success) {
                const events = normalizeHakrawler(hakrawlerResult.stdout, target);
                results.sources.push('hakrawler');

                for (const event of events) {
                    const path = event.payload.path;

                    if (!seenPaths.has(path)) {
                        seenPaths.add(path);
                        ctx.emitEvidence(event);
                        results.endpoints.push(event.payload);

                        if (path.endsWith('.js')) {
                            results.js_files.push(event.payload.url);
                        }
                    }
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'CrawlerAgent',
                    event_type: hakrawlerResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: 'hakrawler', error: hakrawlerResult.error },
                }));
            }
        }

        // Run gau for historical URLs
        if (includeHistorical) {
            const gauAvailable = await isToolAvailable('gau');
            if (gauAvailable) {
                ctx.recordToolInvocation();

                const gauCmd = `gau --subs ${hostname}`;
                const gauOptions = getToolRunOptions('gau', inputs.toolConfig);
                const gauResult = await runToolWithRetry(gauCmd, {
                    ...gauOptions,
                    context: ctx,
                });

                if (gauResult.success) {
                    const events = normalizeGau(gauResult.stdout, target);
                    results.sources.push('gau');

                    for (const event of events) {
                        const path = event.payload.path;

                        if (!seenPaths.has(path)) {
                            seenPaths.add(path);
                            ctx.emitEvidence(event);
                            results.endpoints.push(event.payload);

                            if (path.endsWith('.js')) {
                                results.js_files.push(event.payload.url);
                            }
                        }
                    }
                }
            }

            const gauplusAvailable = await isToolAvailable('gauplus');
            if (gauplusAvailable) {
                ctx.recordToolInvocation();

                const gauplusCmd = `gauplus -subs ${hostname}`;
                const gauplusOptions = getToolRunOptions('gauplus', inputs.toolConfig);
                const gauplusResult = await runToolWithRetry(gauplusCmd, {
                    ...gauplusOptions,
                    context: ctx,
                });

                if (gauplusResult.success) {
                    const events = normalizeGauplus(gauplusResult.stdout, target);
                    results.sources.push('gauplus');

                    for (const event of events) {
                        const path = event.payload.path;

                        if (!seenPaths.has(path)) {
                            seenPaths.add(path);
                            ctx.emitEvidence(event);
                            results.endpoints.push(event.payload);

                            if (path.endsWith('.js')) {
                                results.js_files.push(event.payload.url);
                            }
                        }
                    }
                }
            }

            const waybackAvailable = await isToolAvailable('waybackurls');
            if (waybackAvailable) {
                ctx.recordToolInvocation();

                const waybackCmd = `waybackurls ${hostname}`;
                const waybackOptions = getToolRunOptions('waybackurls', inputs.toolConfig);
                const waybackResult = await runToolWithRetry(waybackCmd, {
                    ...waybackOptions,
                    context: ctx,
                });

                if (waybackResult.success) {
                    const events = normalizeWaybackUrls(waybackResult.stdout, target);
                    results.sources.push('waybackurls');

                    for (const event of events) {
                        const path = event.payload.path;

                        if (!seenPaths.has(path)) {
                            seenPaths.add(path);
                            ctx.emitEvidence(event);
                            results.endpoints.push(event.payload);

                            if (path.endsWith('.js')) {
                                results.js_files.push(event.payload.url);
                            }
                        }
                    }
                }
            }

            const waymoreAvailable = await isToolAvailable('waymore');
            if (waymoreAvailable) {
                ctx.recordToolInvocation();

                const waymoreOptions = getToolRunOptions('waymore', inputs.toolConfig);
                const waymoreCmds = [
                    `waymore -i ${hostname} -mode U`,
                    `waymore -i ${hostname}`,
                ];
                let waymoreResult = null;
                for (const cmd of waymoreCmds) {
                    const result = await runToolWithRetry(cmd, {
                        ...waymoreOptions,
                        context: ctx,
                    });
                    if (result.success) {
                        waymoreResult = result;
                        break;
                    }
                    waymoreResult = result;
                }

                if (waymoreResult && waymoreResult.success) {
                    const events = normalizeWaymore(waymoreResult.stdout, target);
                    results.sources.push('waymore');

                    for (const event of events) {
                        const path = event.payload.path;

                        if (!seenPaths.has(path)) {
                            seenPaths.add(path);
                            ctx.emitEvidence(event);
                            results.endpoints.push(event.payload);

                            if (path.endsWith('.js')) {
                                results.js_files.push(event.payload.url);
                            }
                        }
                    }
                }
            }
        }

        // Emit light claim for endpoint count
        if (results.endpoints.length > 0) {
            ctx.emitClaim({
                claim_type: 'discovery_summary',
                subject: target,
                predicate: {
                    endpoint_count: results.endpoints.length,
                    form_count: results.forms.length,
                    js_file_count: results.js_files.length,
                },
                base_rate: 0.9, // High confidence in discovery
            });
        }

        return results;
    }

    extractHostname(target) {
        try {
            const url = new URL(target);
            return url.hostname;
        } catch {
            return target;
        }
    }
}

export default CrawlerAgent;
