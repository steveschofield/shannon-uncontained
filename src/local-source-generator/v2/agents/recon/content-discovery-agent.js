/**
 * ContentDiscoveryAgent - Hidden content and directory discovery
 * 
 * Uses feroxbuster or ffuf for brute-force discovery of hidden
 * files, directories, and backup files not found by crawling.
 */

import { BaseAgent } from '../base-agent.js';
import { runTool, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';
import { EVENT_TYPES } from '../../worldmodel/evidence-graph.js';

export class ContentDiscoveryAgent extends BaseAgent {
    constructor(options = {}) {
        super('ContentDiscoveryAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL to scan' },
                wordlist: {
                    type: 'string',
                    default: '/usr/share/seclists/Discovery/Web-Content/common.txt',
                    description: 'Path to wordlist file'
                },
                extensions: {
                    type: 'array',
                    items: { type: 'string' },
                    default: ['php', 'bak', 'old', 'txt', 'conf', 'json', 'xml', 'env'],
                    description: 'File extensions to test'
                },
                threads: {
                    type: 'number',
                    default: 50,
                    description: 'Number of concurrent requests (ffuf -t / feroxbuster -t)'
                },
                rateLimit: {
                    type: 'number',
                    description: 'Max requests/second (ffuf -rate). Omit to disable rate limiting.'
                },
                delay: {
                    type: 'string',
                    description: 'Request delay/range (ffuf -p), e.g. \"0.2\" or \"0.2-0.6\" seconds'
                },
                recursionDepth: {
                    type: 'number',
                    default: 2,
                    description: 'Maximum recursion depth'
                },
                tool: {
                    type: 'string',
                    enum: ['feroxbuster', 'ffuf', 'dirsearch', 'gobuster', 'auto', 'all'],
                    default: 'auto',
                    description: 'Tool to use for discovery'
                },
                tools: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Optional list of tools to run (overrides tool)'
                }
            }
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                discovered: { type: 'array' },
                summary: { type: 'object' },
                tool: { type: 'string' },
                tools: { type: 'array', items: { type: 'string' } }
            }
        };

        this.requires = {
            evidence_kinds: ['endpoint_discovered'],
            model_nodes: ['endpoints']
        };

        this.emits = {
            evidence_events: ['hidden_path_discovered', 'backup_file_found', 'config_exposed'],
            model_updates: ['endpoint_added'],
            claims: ['sensitive_file_exposed', 'backup_accessible', 'directory_listing'],
            artifacts: ['content_discovery_results.json']
        };

        this.default_budget = {
            max_time_ms: 300000,
            max_network_requests: 10000,
            max_tokens: 0,
            max_tool_invocations: 4
        };

        // Interesting paths patterns
        this.sensitivePatterns = [
            /\.git/i,
            /\.env/i,
            /\.htaccess/i,
            /\.htpasswd/i,
            /backup/i,
            /admin/i,
            /config/i,
            /database/i,
            /\.sql/i,
            /\.bak/i,
            /\.old/i,
            /\.swp/i,
            /\.log/i,
            /phpinfo/i,
            /\.DS_Store/i,
            /web\.config/i,
            /wp-config/i,
        ];
    }

    /**
     * Detect which tool is available
     */
    async detectTool() {
        if (await isToolAvailable('feroxbuster')) {
            return 'feroxbuster';
        }
        if (await isToolAvailable('dirsearch')) {
            return 'dirsearch';
        }
        if (await isToolAvailable('ffuf')) {
            return 'ffuf';
        }
        if (await isToolAvailable('gobuster')) {
            return 'gobuster';
        }
        return null;
    }

    async resolveTools(tool, tools) {
        if (Array.isArray(tools) && tools.length > 0) {
            return tools;
        }
        if (tool === 'all') {
            const candidates = ['feroxbuster', 'dirsearch', 'ffuf', 'gobuster'];
            const available = [];
            for (const candidate of candidates) {
                if (await isToolAvailable(candidate)) {
                    available.push(candidate);
                }
            }
            return available;
        }
        if (tool === 'auto') {
            const selected = await this.detectTool();
            return selected ? [selected] : [];
        }
        return tool ? [tool] : [];
    }

    /**
     * Build feroxbuster command
     */
    buildFeroxbusterCommand(inputs) {
        const { target, wordlist, extensions, threads, recursionDepth } = inputs;

        let cmd = `feroxbuster -u "${target}" -w "${wordlist}"`;
        cmd += ` -t ${threads}`;
        cmd += ` -d ${recursionDepth}`;
        cmd += ` -x ${extensions.join(',')}`;
        cmd += ' --json';
        // Newer feroxbuster requires one of: --debug-log | --output | --silent
        // Use --silent to satisfy the requirement while keeping stdout-only JSON
        cmd += ' --silent';
        cmd += ' --no-state';

        return cmd;
    }

    /**
     * Build ffuf command
     */
    buildFfufCommand(inputs) {
        const { target, wordlist, extensions, threads, rateLimit, delay } = inputs;

        // Ensure target has FUZZ keyword
        const fuzzTarget = target.endsWith('/') ? `${target}FUZZ` : `${target}/FUZZ`;

        let cmd = `ffuf -u "${fuzzTarget}" -w "${wordlist}"`;
        cmd += ` -t ${threads}`;
        if (typeof rateLimit === 'number' && Number.isFinite(rateLimit) && rateLimit > 0) {
            cmd += ` -rate ${rateLimit}`;
        }
        if (delay) {
            cmd += ` -p "${delay}"`;
        }
        cmd += ` -e ${extensions.map(e => `.${e}`).join(',')}`;
        cmd += ' -o /dev/stdout -of json';
        cmd += ' -s';  // Silent mode
        cmd += ' -mc 200,201,204,301,302,307,401,403';  // Match codes

        return cmd;
    }

    /**
     * Build dirsearch command
     */
    buildDirsearchCommand(inputs, outputFile = null) {
        const { target, wordlist, extensions, threads } = inputs;

        let cmd = `dirsearch -u "${target}" -w "${wordlist}"`;
        if (extensions.length > 0) {
            cmd += ` -e ${extensions.join(',')}`;
        }
        cmd += ` -t ${threads}`;
        if (outputFile) {
            cmd += ` --format json --output "${outputFile}"`;
        }

        return cmd;
    }

    /**
     * Build gobuster command
     */
    buildGobusterCommand(inputs) {
        const { target, wordlist, extensions, threads } = inputs;
        const extFlag = extensions.length > 0 ? ` -x ${extensions.map(e => `.${e}`).join(',')}` : '';

        let cmd = `gobuster dir -u "${target}" -w "${wordlist}"`;
        cmd += ` -t ${threads}`;
        cmd += extFlag;
        cmd += ' -q';
        cmd += ' -s 200,201,204,301,302,307,401,403';

        return cmd;
    }

    /**
     * Parse feroxbuster JSON output
     */
    parseFeroxbusterOutput(stdout) {
        const discovered = [];
        const lines = stdout.split('\n').filter(l => l.trim());

        for (const line of lines) {
            try {
                const entry = JSON.parse(line);
                if (entry.type === 'response' && entry.status) {
                    discovered.push({
                        url: entry.url,
                        path: new URL(entry.url).pathname,
                        status: entry.status,
                        size: entry.content_length || entry.word_count,
                        method: 'GET'
                    });
                }
            } catch { }
        }

        return discovered;
    }

    /**
     * Parse ffuf JSON output
     */
    parseFfufOutput(stdout) {
        const discovered = [];

        try {
            const data = JSON.parse(stdout);
            for (const result of data.results || []) {
                discovered.push({
                    url: result.url,
                    path: new URL(result.url).pathname,
                    status: result.status,
                    size: result.length,
                    words: result.words,
                    lines: result.lines
                });
            }
        } catch { }

        return discovered;
    }

    /**
     * Parse dirsearch JSON output (file or stdout)
     */
    parseDirsearchOutput(stdout) {
        const discovered = [];
        const trimmed = stdout.trim();

        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            try {
                const data = JSON.parse(trimmed);
                const entries = Array.isArray(data) ? data : (data.results || []);
                for (const result of entries) {
                    if (!result.url) continue;
                    let pathValue = result.path;
                    try {
                        pathValue = pathValue || new URL(result.url).pathname;
                    } catch {}
                    discovered.push({
                        url: result.url,
                        path: pathValue,
                        status: result.status || result.code,
                        size: result.length || result.size || result.words,
                        method: result.method || 'GET'
                    });
                }
                return discovered;
            } catch {}
        }

        // Fallback: parse line output
        const lines = stdout.split('\n').filter(l => l.trim());
        for (const line of lines) {
            const match = line.match(/(\d{3}).*?(https?:\/\/\S+|\/\S+)/);
            if (match) {
                const status = parseInt(match[1], 10);
                const url = match[2].startsWith('http')
                    ? match[2]
                    : null;
                const pathValue = url ? new URL(url).pathname : match[2];
                discovered.push({
                    url: url || match[2],
                    path: pathValue,
                    status,
                    method: 'GET'
                });
            }
        }

        return discovered;
    }

    /**
     * Parse gobuster output
     */
    parseGobusterOutput(stdout, baseUrl) {
        const discovered = [];
        const lines = stdout.split('\n').filter(l => l.trim());

        for (const line of lines) {
            const match = line.match(/^(\S+)\s+\(Status:\s*(\d{3})/i);
            if (match) {
                const pathValue = match[1];
                const status = parseInt(match[2], 10);
                const url = pathValue.startsWith('http') ? pathValue : new URL(pathValue, baseUrl).toString();
                discovered.push({
                    url,
                    path: new URL(url).pathname,
                    status,
                    method: 'GET'
                });
            }
        }

        return discovered;
    }

    /**
     * Classify discovered path
     */
    classifyPath(path) {
        const classifications = [];

        for (const pattern of this.sensitivePatterns) {
            if (pattern.test(path)) {
                if (/\.git/i.test(path)) classifications.push('git_exposed');
                else if (/\.env/i.test(path)) classifications.push('env_exposed');
                else if (/backup|\.bak|\.old/i.test(path)) classifications.push('backup_file');
                else if (/config|\.conf/i.test(path)) classifications.push('config_exposed');
                else if (/admin/i.test(path)) classifications.push('admin_panel');
                else if (/\.sql/i.test(path)) classifications.push('database_file');
                else if (/\.log/i.test(path)) classifications.push('log_exposed');
                else classifications.push('sensitive_file');
            }
        }

        return classifications.length > 0 ? classifications : ['discovered'];
    }

    /**
     * Main execution
     */
    async run(ctx, inputs) {
        const {
            target,
            wordlist = '/usr/share/seclists/Discovery/Web-Content/common.txt',
            extensions = ['php', 'bak', 'old', 'txt', 'conf', 'json', 'xml', 'env'],
            threads: providedThreads,
            rateLimit: providedRateLimit,
            delay: providedDelay,
            recursionDepth = 2,
            tool = 'auto',
            tools = null,
        } = inputs;

        // Apply safer defaults based on selected profile if not explicitly set
        const profile = inputs.rateLimitProfile || 'normal';
        const profileDefaults = {
            stealth: { threads: 5, rateLimit: 5, delay: '0.3-0.7' },
            conservative: { threads: 10, rateLimit: 10, delay: '0.2-0.5' },
            normal: { threads: 25, rateLimit: 25, delay: '0.1-0.3' },
            aggressive: { threads: 50, rateLimit: 0, delay: '' },
        };
        const defaults = profileDefaults[profile] || profileDefaults.normal;
        const threads = (typeof providedThreads === 'number' && Number.isFinite(providedThreads) && providedThreads > 0)
            ? providedThreads
            : defaults.threads;
        const rateLimit = (typeof providedRateLimit === 'number' && Number.isFinite(providedRateLimit) && providedRateLimit >= 0)
            ? providedRateLimit
            : defaults.rateLimit;
        const delay = (typeof providedDelay === 'string' && providedDelay.trim().length > 0)
            ? providedDelay.trim()
            : defaults.delay;

        // Resolve a usable wordlist path across OS layouts
        const { fs, path } = await import('zx');
        let resolvedWordlist = wordlist;
        const candidates = [
            wordlist,
            '/opt/homebrew/opt/seclists/share/seclists/Discovery/Web-Content/common.txt', // macOS arm64 brew
            '/usr/local/opt/seclists/share/seclists/Discovery/Web-Content/common.txt',    // macOS intel brew
            '/usr/share/seclists/Discovery/Web-Content/common.txt',                      // Debian/Ubuntu
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        ];
        for (const cand of candidates) {
            try { if (await fs.pathExists(cand)) { resolvedWordlist = cand; break; } } catch {}
        }
        // Create a minimal fallback if none of the candidates exist
        if (!(await fs.pathExists(resolvedWordlist))) {
            const baseDir = inputs.outputDir || process.cwd();
            const fallback = path.join(baseDir, 'config', 'wordlists');
            await fs.ensureDir(fallback);
            resolvedWordlist = path.join(fallback, 'minimal.txt');
            const minimal = [
                'robots.txt', 'sitemap.xml', 'admin', 'login', 'assets', 'static', 'api', 'config', 'backup',
            ].join('\n');
            try { await fs.writeFile(resolvedWordlist, minimal); } catch {}
        }

        // Resolve tools to run
        const toolList = await this.resolveTools(tool, tools);

        if (!toolList.length) {
            return {
                discovered: [],
                error: 'No content discovery tool available. Install feroxbuster, ffuf, dirsearch, or gobuster.',
                tool: null,
                tools: [],
                summary: { total: 0 }
            };
        }

        const discovered = [];
        const seenUrls = new Set();
        const summary = {
            total: 0,
            byStatus: {},
            byClassification: {},
            byTool: {},
            sensitive: 0
        };

        const baseTmp = inputs.outputDir || process.cwd();
        await fs.ensureDir(baseTmp);
        const tmpDir = await fs.mkdtemp(path.join(baseTmp, 'tmp-content-'));

        for (const selectedTool of toolList) {
            let command = null;
            let parseFn = null;
            let toolOutputFile = null;

            if (selectedTool === 'feroxbuster') {
                command = this.buildFeroxbusterCommand({ target, wordlist: resolvedWordlist, extensions, threads, recursionDepth });
                parseFn = (stdout) => this.parseFeroxbusterOutput(stdout);
            } else if (selectedTool === 'ffuf') {
                command = this.buildFfufCommand({ target, wordlist: resolvedWordlist, extensions, threads, rateLimit, delay });
                parseFn = (stdout) => this.parseFfufOutput(stdout);
            } else if (selectedTool === 'dirsearch') {
                toolOutputFile = path.join(tmpDir, 'dirsearch.json');
                command = this.buildDirsearchCommand({ target, wordlist: resolvedWordlist, extensions, threads }, toolOutputFile);
                parseFn = (stdout) => this.parseDirsearchOutput(stdout);
            } else if (selectedTool === 'gobuster') {
                command = this.buildGobusterCommand({ target, wordlist: resolvedWordlist, extensions, threads });
                parseFn = (stdout) => this.parseGobusterOutput(stdout, target);
            }

            if (!command || !parseFn) {
                continue;
            }

            ctx.recordToolInvocation();
            const toolOptions = getToolRunOptions(selectedTool, inputs.toolConfig);
            let result = await runTool(command, { timeout: toolOptions.timeout, context: ctx });

            if (!result.success && selectedTool === 'dirsearch') {
                const fallback = this.buildDirsearchCommand({ target, wordlist: resolvedWordlist, extensions, threads }, null);
                result = await runTool(fallback, { timeout: toolOptions.timeout, context: ctx });
            }

            if (!result.success) {
                ctx.emitEvidence({
                    source: this.name,
                    event_type: result.timedOut ? EVENT_TYPES.TOOL_TIMEOUT : EVENT_TYPES.TOOL_ERROR,
                    target,
                    payload: { tool: selectedTool, error: result.error },
                });
                continue;
            }

            let output = result.stdout || '';
            if (selectedTool === 'dirsearch' && toolOutputFile) {
                output = await this.readIfExists(fs, toolOutputFile, output);
            }

            const parsed = parseFn(output) || [];
            summary.byTool[selectedTool] = (summary.byTool[selectedTool] || 0) + parsed.length;

            for (const item of parsed) {
                const url = item.url || (item.path ? new URL(item.path, target).toString() : null);
                if (!url || seenUrls.has(url)) continue;
                seenUrls.add(url);
                item.url = url;
                try {
                    item.path = new URL(url).pathname;
                } catch {}
                item.source = selectedTool;
                discovered.push(item);
            }
        }

        // Process and emit evidence for each discovery
        summary.total = discovered.length;
        for (const item of discovered) {
            ctx.recordNetworkRequest();

            const classifications = this.classifyPath(item.path);
            item.classifications = classifications;

            // Count by status
            summary.byStatus[item.status] = (summary.byStatus[item.status] || 0) + 1;

            // Count by classification
            for (const cls of classifications) {
                summary.byClassification[cls] = (summary.byClassification[cls] || 0) + 1;
            }

            // Detect sensitive files
            const isSensitive = classifications.some(c => c !== 'discovered');
            if (isSensitive) {
                summary.sensitive++;

                // Emit evidence
                const evidenceId = ctx.emitEvidence({
                    type: classifications.includes('backup_file') ? 'backup_file_found' :
                        classifications.includes('config_exposed') ? 'config_exposed' :
                            'hidden_path_discovered',
                    source: this.name,
                    data: item
                });

                // Emit claim
                ctx.emitClaim({
                    claim_type: 'sensitive_file_exposed',
                    subject: item.url,
                    predicate: {
                        path: item.path,
                        status: item.status,
                        classifications
                    },
                    base_rate: 0.2
                });

                // Add EBSL evidence
                ctx.ledger.addEvidence(
                    ctx.ledger.generateClaimId('sensitive_file_exposed', item.url),
                    'active_probe_success',
                    0.9,
                    this.name,
                    evidenceId
                );
            }
        }

        return {
            discovered,
            tool: toolList[0] || null,
            tools: toolList,
            summary
        };
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

export default ContentDiscoveryAgent;
