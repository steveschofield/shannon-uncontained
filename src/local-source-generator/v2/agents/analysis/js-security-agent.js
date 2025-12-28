/**
 * JSSecurityAgent - JS dependency + secret scanning
 *
 * Uses retire.js and SecretFinder (when available) to flag vulnerable JS
 * libraries and exposed secrets in client-side bundles.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';

export class JSSecurityAgent extends BaseAgent {
    constructor(options = {}) {
        super('JSSecurityAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                max_js_files: { type: 'number', description: 'Max JS files to scan' },
                use_retirejs: { type: 'boolean', description: 'Enable retire.js scanning' },
                use_secretfinder: { type: 'boolean', description: 'Enable SecretFinder scanning' },
                secretfinder_max_files: { type: 'number', description: 'Max JS files to scan with SecretFinder' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                secrets: { type: 'array', items: { type: 'object' } },
                js_files: { type: 'array', items: { type: 'string' } },
            },
        };

        this.requires = { evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED], model_nodes: [] };
        this.emits = {
            evidence_events: ['js_vulnerability_found', 'js_secret_found', EVENT_TYPES.TOOL_ERROR],
            model_updates: [],
            claims: [],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 180000,
            max_network_requests: 200,
            max_tokens: 0,
            max_tool_invocations: 6,
        };
    }

    async run(ctx, inputs) {
        const {
            target,
            max_js_files: maxJsFilesInput,
            use_retirejs: useRetireInput,
            use_secretfinder: useSecretFinderInput,
            secretfinder_max_files: secretFinderMaxInput,
        } = inputs;

        const toolConfig = inputs.toolConfig || ctx.config?.toolConfig || null;
        const maxJsFiles = Number.isFinite(maxJsFilesInput) ? Math.max(1, maxJsFilesInput) : 25;
        const useRetire = useRetireInput !== false;
        const useSecretFinder = useSecretFinderInput !== false;
        const secretFinderMax = Number.isFinite(secretFinderMaxInput) ? Math.max(1, secretFinderMaxInput) : 10;

        const jsFiles = this.collectJsFiles(ctx).slice(0, maxJsFiles);
        const results = { vulnerabilities: [], secrets: [], js_files: jsFiles };

        if (jsFiles.length === 0) {
            return results;
        }

        const workspaceDir = inputs.outputDir || inputs.workspace || process.cwd();

        if (useRetire && await isToolAvailable('retire')) {
            const retireFindings = await this.runRetire(ctx, jsFiles, toolConfig, target, workspaceDir);
            results.vulnerabilities.push(...retireFindings);
        }

        if (useSecretFinder) {
            const secretFinderCmd = await this.resolveSecretFinderCommand();
            if (secretFinderCmd) {
                const secrets = await this.runSecretFinder(ctx, jsFiles.slice(0, secretFinderMax), secretFinderCmd, toolConfig, target);
                results.secrets.push(...secrets);
            }
        }

        return results;
    }

    collectJsFiles(ctx) {
        const events = ctx.evidenceGraph.getEventsByType(EVENT_TYPES.ENDPOINT_DISCOVERED) || [];
        const jsFiles = new Set();
        for (const event of events) {
            const url = event.payload?.url || event.payload?.endpoint;
            if (typeof url === 'string' && url.includes('.js')) {
                jsFiles.add(url);
            }
        }
        return Array.from(jsFiles);
    }

    async runRetire(ctx, jsFiles, toolConfig, target, workspaceDir) {
        const { fs, path } = await import('zx');
        await fs.ensureDir(workspaceDir);
        const tmpDir = await fs.mkdtemp(path.join(workspaceDir, 'tmp-retire-'));
        const downloaded = await this.downloadJsFiles(jsFiles, tmpDir);
        if (downloaded.length === 0) return [];

        ctx.recordToolInvocation();
        const toolOptions = getToolRunOptions('retire', toolConfig);
        const cmd = `retire --path "${tmpDir}" --outputformat json`;
        const result = await runToolWithRetry(cmd, {
            ...toolOptions,
            context: ctx,
        });

        if (!result.success) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                target,
                payload: { tool: 'retire', error: result.error },
            }));
            return [];
        }

        const findings = this.parseRetireOutput(result.stdout);
        for (const finding of findings) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: 'js_vulnerability_found',
                target,
                payload: finding,
            }));
        }

        return findings;
    }

    parseRetireOutput(stdout) {
        const findings = [];
        if (!stdout) return findings;
        try {
            const data = JSON.parse(stdout);
            const entries = data.data || data.results || data || [];
            for (const entry of Array.isArray(entries) ? entries : []) {
                const file = entry.file || entry.filePath || entry.path;
                for (const result of entry.results || []) {
                    const component = result.component || result.library;
                    const version = result.version || result.detectedVersion;
                    const vulns = result.vulnerabilities || [];
                    for (const vuln of vulns) {
                        findings.push({
                            file,
                            component,
                            version,
                            severity: vuln.severity || null,
                            identifiers: vuln.identifiers || null,
                            info: vuln.info || null,
                        });
                    }
                }
            }
        } catch {}
        return findings;
    }

    async runSecretFinder(ctx, jsFiles, command, toolConfig, target) {
        const findings = [];

        for (const jsUrl of jsFiles) {
            ctx.recordToolInvocation();
            const toolOptions = getToolRunOptions('secretfinder', toolConfig);
            const cmd = `${command} -i "${jsUrl}" -o json`;
            const result = await runToolWithRetry(cmd, {
                ...toolOptions,
                context: ctx,
            });

            if (!result.success) {
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: 'secretfinder', error: result.error, url: jsUrl },
                }));
                continue;
            }

            const parsed = this.parseSecretFinderOutput(result.stdout);
            for (const finding of parsed) {
                const record = { ...finding, source_url: jsUrl };
                findings.push(record);
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'js_secret_found',
                    target,
                    payload: record,
                }));
            }
        }

        return findings;
    }

    parseSecretFinderOutput(stdout) {
        const findings = [];
        if (!stdout) return findings;
        try {
            const data = JSON.parse(stdout);
            if (Array.isArray(data)) {
                return data.map(item => ({ match: item }));
            }
            if (data && typeof data === 'object') {
                for (const [key, value] of Object.entries(data)) {
                    if (Array.isArray(value)) {
                        for (const entry of value) {
                            findings.push({ category: key, match: entry });
                        }
                    } else if (value) {
                        findings.push({ category: key, match: value });
                    }
                }
            }
        } catch {
            const lines = String(stdout).split('\n').map(l => l.trim()).filter(Boolean);
            for (const line of lines) {
                findings.push({ match: line });
            }
        }
        return findings;
    }

    async resolveSecretFinderCommand() {
        if (await isToolAvailable('secretfinder')) return 'secretfinder';
        if (await isToolAvailable('SecretFinder.py')) return 'SecretFinder.py';
        return null;
    }

    async downloadJsFiles(jsFiles, dir) {
        const { fs, path } = await import('zx');
        const downloaded = [];

        for (const jsUrl of jsFiles) {
            try {
                const response = await fetch(jsUrl, {
                    headers: { 'User-Agent': 'Mozilla/5.0 Shannon-LSG/2.0' },
                });
                if (!response.ok) continue;
                const content = await response.text();
                const name = `${this.slugify(jsUrl)}.js`;
                const filePath = path.join(dir, name);
                await fs.writeFile(filePath, content);
                downloaded.push(filePath);
            } catch {}
        }

        return downloaded;
    }

    slugify(value) {
        return value.replace(/[^a-z0-9]+/gi, '-').slice(0, 60);
    }
}

export default JSSecurityAgent;
