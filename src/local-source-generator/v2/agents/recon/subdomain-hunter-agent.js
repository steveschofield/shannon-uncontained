/**
 * SubdomainHunterAgent - Subdomain enumeration agent
 * 
 * Discovers subdomains via DNS, certificate transparency, and passive sources.
 */

import { BaseAgent } from '../base-agent.js';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';
import { normalizeSubfinder, normalizeAmass } from '../../tools/normalizers/evidence-normalizers.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';

export class SubdomainHunterAgent extends BaseAgent {
    constructor(options = {}) {
        super('SubdomainHunterAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target domain' },
                passive_only: { type: 'boolean', description: 'Use only passive sources' },
                resolvers_file: { type: 'string', description: 'Optional DNS resolvers file for shuffledns/puredns' },
                permutation_wordlist: { type: 'string', description: 'Wordlist for altdns permutations' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                subdomains: { type: 'array', items: { type: 'string' } },
                sources: { type: 'array', items: { type: 'string' } },
            },
        };

        this.requires = { evidence_kinds: [], model_nodes: [] };
        this.emits = {
            evidence_events: [EVENT_TYPES.DNS_RECORD],
            model_updates: [],
            claims: [],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 120000,
            max_network_requests: 500,
            max_tokens: 0,
            max_tool_invocations: 9,
        };
    }

    async run(ctx, inputs) {
        const { target, passive_only = true } = inputs;
        const domain = this.extractDomain(target);

        const results = {
            subdomains: [],
            sources: [],
        };

        const seenSubdomains = new Set();
        const sourceSet = new Set();

        // Run subfinder
        const subfinderAvailable = await isToolAvailable('subfinder');
        if (subfinderAvailable) {
            ctx.recordToolInvocation();

            const flags = passive_only ? '' : '-active';
            const subfinderCmd = `subfinder -d ${domain} -silent ${flags}`;
            const subfinderOptions = getToolRunOptions('subfinder', inputs.toolConfig);
            const result = await runToolWithRetry(subfinderCmd, {
                ...subfinderOptions,
                context: ctx,
            });

            if (result.success) {
                const events = normalizeSubfinder(result.stdout, domain);
                sourceSet.add('subfinder');

                for (const event of events) {
                    const subdomain = event.payload.subdomain;
                    if (!seenSubdomains.has(subdomain)) {
                        seenSubdomains.add(subdomain);
                        ctx.emitEvidence(event);
                        results.subdomains.push(subdomain);
                    }
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'subfinder', error: result.error },
                }));
            }
        }

        const amassAvailable = await isToolAvailable('amass');
        if (amassAvailable) {
            ctx.recordToolInvocation();

            const amassFlags = passive_only ? '-passive' : '-active';
            const amassCmd = `amass enum ${amassFlags} -d ${domain} -norecursive -silent`;
            const amassOptions = getToolRunOptions('amass', inputs.toolConfig);
            const amassResult = await runToolWithRetry(amassCmd, {
                ...amassOptions,
                context: ctx,
            });

            if (amassResult.success) {
                const events = normalizeAmass(amassResult.stdout, domain);
                sourceSet.add('amass');

                for (const event of events) {
                    const subdomain = event.payload.subdomain;
                    if (!seenSubdomains.has(subdomain)) {
                        seenSubdomains.add(subdomain);
                        ctx.emitEvidence(event);
                        results.subdomains.push(subdomain);
                    }
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: amassResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'amass', error: amassResult.error },
                }));
            }
        }

        // Query crt.sh for certificate transparency
        ctx.recordNetworkRequest();
        try {
            const crtshUrl = `https://crt.sh/?q=%25.${domain}&output=json`;
            const response = await fetch(crtshUrl, {
                headers: { 'User-Agent': 'Mozilla/5.0 Shannon-LSG/2.0' },
            });

            if (response.ok) {
                const data = await response.json();
                sourceSet.add('crt.sh');

                for (const cert of data) {
                    const names = cert.name_value?.split('\n') || [];
                    for (const name of names) {
                        const subdomain = name.trim().replace(/^\*\./, '');
                        if (subdomain.endsWith(domain) && !seenSubdomains.has(subdomain)) {
                            seenSubdomains.add(subdomain);
                            results.subdomains.push(subdomain);

                            ctx.emitEvidence(createEvidenceEvent({
                                source: 'crt.sh',
                                event_type: EVENT_TYPES.TLS_CERT,
                                target: domain,
                                payload: {
                                    subdomain,
                                    issuer: cert.issuer_name,
                                    not_before: cert.not_before,
                                    not_after: cert.not_after,
                                },
                            }));
                        }
                    }
                }
            }
        } catch {
            // Ignore crt.sh errors
        }

        // Optional permutation generation + resolution
        const { fs, path } = await import('zx');
        const workspaceDir = inputs.outputDir || inputs.workspace || process.cwd();
        await fs.ensureDir(workspaceDir);
        const tmpRoot = await fs.mkdtemp(path.join(workspaceDir, 'tmp-subdomains-'));
        const seedFile = path.join(tmpRoot, 'subdomains.txt');
        const seedList = Array.from(seenSubdomains);
        if (seedList.length > 0) {
            await fs.writeFile(seedFile, seedList.join('\n') + '\n');
        }

        const resolverFile = await this.resolveResolversFile(fs, inputs.resolvers_file);
        const permutationWordlist = await this.resolvePermutationWordlist(fs, inputs.permutation_wordlist);

        const candidateSubdomains = new Set(seenSubdomains);

        const altdnsAvailable = await isToolAvailable('altdns');
        if (altdnsAvailable && permutationWordlist && seedList.length > 0) {
            ctx.recordToolInvocation();
            const outputFile = path.join(tmpRoot, 'altdns-output.txt');
            const altdnsCmd = `altdns -i "${seedFile}" -o "${outputFile}" -w "${permutationWordlist}"`;
            const altdnsOptions = getToolRunOptions('altdns', inputs.toolConfig);
            const altdnsResult = await runToolWithRetry(altdnsCmd, {
                ...altdnsOptions,
                context: ctx,
            });

            if (altdnsResult.success) {
                sourceSet.add('altdns');
                const altdnsOutput = await this.readIfExists(fs, outputFile, altdnsResult.stdout);
                for (const line of this.parseSubdomainLines(altdnsOutput, domain)) {
                    candidateSubdomains.add(line);
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: altdnsResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'altdns', error: altdnsResult.error },
                }));
            }
        }

        const listFile = path.join(tmpRoot, 'candidates.txt');
        const candidateList = Array.from(candidateSubdomains);
        if (candidateList.length > 0) {
            await fs.writeFile(listFile, candidateList.join('\n') + '\n');
        }

        const dnsxAvailable = await isToolAvailable('dnsx');
        if (dnsxAvailable && candidateList.length > 0) {
            ctx.recordToolInvocation();
            const dnsxCmd = `dnsx -silent -l "${listFile}"`;
            const dnsxOptions = getToolRunOptions('dnsx', inputs.toolConfig);
            const dnsxResult = await runToolWithRetry(dnsxCmd, {
                ...dnsxOptions,
                context: ctx,
            });

            if (dnsxResult.success) {
                sourceSet.add('dnsx');
                const resolved = this.parseSubdomainLines(dnsxResult.stdout, domain);
                for (const subdomain of resolved) {
                    this.addResolvedSubdomain(ctx, results, seenSubdomains, subdomain, 'dnsx');
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: dnsxResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'dnsx', error: dnsxResult.error },
                }));
            }
        }

        const shufflednsAvailable = await isToolAvailable('shuffledns');
        if (shufflednsAvailable && resolverFile && candidateList.length > 0) {
            ctx.recordToolInvocation();
            const shufflednsCmd = `shuffledns -list "${listFile}" -r "${resolverFile}" -silent`;
            const shufflednsOptions = getToolRunOptions('shuffledns', inputs.toolConfig);
            const shufflednsResult = await runToolWithRetry(shufflednsCmd, {
                ...shufflednsOptions,
                context: ctx,
            });

            if (shufflednsResult.success) {
                sourceSet.add('shuffledns');
                const resolved = this.parseSubdomainLines(shufflednsResult.stdout, domain);
                for (const subdomain of resolved) {
                    this.addResolvedSubdomain(ctx, results, seenSubdomains, subdomain, 'shuffledns');
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: shufflednsResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'shuffledns', error: shufflednsResult.error },
                }));
            }
        }

        const purednsAvailable = await isToolAvailable('puredns');
        if (purednsAvailable && resolverFile && candidateList.length > 0) {
            ctx.recordToolInvocation();
            const purednsCmd = `puredns resolve "${listFile}" -r "${resolverFile}"`;
            const purednsOptions = getToolRunOptions('puredns', inputs.toolConfig);
            const purednsResult = await runToolWithRetry(purednsCmd, {
                ...purednsOptions,
                context: ctx,
            });

            if (purednsResult.success) {
                sourceSet.add('puredns');
                const resolved = this.parseSubdomainLines(purednsResult.stdout, domain);
                for (const subdomain of resolved) {
                    this.addResolvedSubdomain(ctx, results, seenSubdomains, subdomain, 'puredns');
                }
            } else {
                ctx.emitEvidence(createEvidenceEvent({
                    source: 'SubdomainHunterAgent',
                    event_type: purednsResult.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target: domain,
                    payload: { tool: 'puredns', error: purednsResult.error },
                }));
            }
        }

        results.sources = Array.from(sourceSet);

        return results;
    }

    extractDomain(target) {
        try {
            const url = new URL(target);
            return url.hostname;
        } catch {
            // Already a domain
            return target.replace(/^www\./, '');
        }
    }

    parseSubdomainLines(output, domain) {
        const lines = String(output || '').split('\n').map(l => l.trim()).filter(Boolean);
        const results = [];
        for (const line of lines) {
            const candidate = line.split(/\s+/)[0].replace(/^\*\./, '').trim();
            if (!candidate) continue;
            if (domain && !candidate.endsWith(domain)) continue;
            results.push(candidate.toLowerCase());
        }
        return results;
    }

    addResolvedSubdomain(ctx, results, seenSubdomains, subdomain, sourceTool) {
        if (!subdomain || seenSubdomains.has(subdomain)) return;
        seenSubdomains.add(subdomain);
        results.subdomains.push(subdomain);
        ctx.emitEvidence(createEvidenceEvent({
            source: sourceTool,
            event_type: EVENT_TYPES.DNS_RECORD,
            target: subdomain,
            payload: {
                subdomain,
                record_type: 'subdomain',
                source: sourceTool,
            },
        }));
    }

    async resolvePermutationWordlist(fs, provided) {
        const candidates = [
            provided,
            '/usr/share/seclists/Discovery/DNS/altdns.txt',
            '/usr/share/wordlists/amass/words.txt',
            '/usr/share/seclists/Discovery/DNS/namelist.txt',
        ].filter(Boolean);
        for (const cand of candidates) {
            try {
                if (await fs.pathExists(cand)) return cand;
            } catch {}
        }
        return null;
    }

    async resolveResolversFile(fs, provided) {
        const candidates = [
            provided,
            '/usr/share/seclists/Discovery/DNS/resolvers.txt',
            '/usr/share/seclists/Discovery/DNS/resolvers-public.txt',
            '/usr/share/wordlists/dnsrecon/resolvers.txt',
        ].filter(Boolean);
        for (const cand of candidates) {
            try {
                if (await fs.pathExists(cand)) return cand;
            } catch {}
        }
        return null;
    }

    async readIfExists(fs, filePath, fallback = '') {
        try {
            if (await fs.pathExists(filePath)) {
                return await fs.readFile(filePath, 'utf-8');
            }
        } catch {}
        return fallback || '';
    }
}

export default SubdomainHunterAgent;
