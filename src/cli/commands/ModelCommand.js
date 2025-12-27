
import chalk from 'chalk';
import { fs, path } from 'zx';

export async function modelCommand(action, arg, options) {
    const workspace = options.workspace || '.';
    const worldModelFile = path.join(workspace, 'world-model.json');

    if (!await fs.pathExists(worldModelFile)) {
        console.error(chalk.red(`No world model found at ${worldModelFile}`));
        process.exit(1);
    }

    const data = await fs.readJSON(worldModelFile);

    switch (action) {
        case 'why':
            explainClaim(arg, data);
            break;
        case 'show':
            showModelVisualization(data, options);
            break;
        case 'graph':
            showGraph(data);
            break;
        case 'export-html':
            await exportHtmlGraph(data, options);
            break;
        case 'export-review':
            await exportHtmlReview(data, options, workspace);
            break;
        case 'export-proxy':
            await exportProxyBundle(data, options, workspace);
            break;
        default:
            console.log(chalk.red(`Unknown action: ${action}`));
    }
}

function explainClaim(claimId, data) {
    const claim = data.claims.find(c => c.id === claimId || c.subject === claimId);

    if (!claim) {
        console.log(chalk.red(`Claim '${claimId}' not found.`));
        return;
    }

    console.log(chalk.bold(`\n🧐 Explanation for Claim: ${claim.id}`));
    console.log(`Subject:   ${chalk.cyan(claim.subject)}`);
    console.log(`Predicate: ${chalk.yellow(claim.predicate)}`);
    console.log(`Object:    ${chalk.green(JSON.stringify(claim.object))}`);
    console.log(`Confidence: ${renderConfidenceBar(claim.confidence)}`);

    console.log(chalk.bold('\nBased on Evidence:'));
    claim.evidenceIds.forEach(eid => {
        const ev = data.evidence.find(e => e.id === eid);
        if (ev) {
            console.log(`  - [${ev.id.substring(0, 8)}] (${ev.sourceAgent}) ${JSON.stringify(ev.content).substring(0, 60)}...`);
        } else {
            console.log(`  - [${eid}] (Missing evidence data)`);
        }
    });
}

function showModelVisualization(data, options) {
    console.log(chalk.bold.cyan('\n╔════════════════════════════════════════════════════════════╗'));
    console.log(chalk.bold.cyan('║              🌐 WORLD MODEL VISUALIZATION                    ║'));
    console.log(chalk.bold.cyan('╚════════════════════════════════════════════════════════════╝\n'));

    // Summary Stats
    console.log(chalk.bold('📊 Summary'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(`  Evidence Items:  ${chalk.cyan(data.evidence?.length || 0)}`);
    console.log(`  Claims:          ${chalk.green(data.claims?.length || 0)}`);
    console.log(`  Artifacts:       ${chalk.yellow(data.artifacts?.length || 0)}`);
    console.log(`  Relations:       ${chalk.magenta(data.relations?.length || 0)}`);
    console.log();

    // Evidence by Agent Chart
    if (data.evidence?.length > 0) {
        console.log(chalk.bold('📈 Evidence by Agent'));
        console.log(chalk.gray('─'.repeat(50)));
        const byAgent = {};
        data.evidence.forEach(e => {
            byAgent[e.sourceAgent] = (byAgent[e.sourceAgent] || 0) + 1;
        });
        renderBarChart(byAgent);
        console.log();
    }

    // Confidence Distribution
    if (data.claims?.length > 0) {
        console.log(chalk.bold('🎯 Claim Confidence Distribution'));
        console.log(chalk.gray('─'.repeat(50)));
        const buckets = { 'High (0.8-1.0)': 0, 'Medium (0.5-0.8)': 0, 'Low (0-0.5)': 0 };
        data.claims.forEach(c => {
            if (c.confidence >= 0.8) buckets['High (0.8-1.0)']++;
            else if (c.confidence >= 0.5) buckets['Medium (0.5-0.8)']++;
            else buckets['Low (0-0.5)']++;
        });
        renderBarChart(buckets);
        console.log();
    }

    // Top Claims
    if (data.claims?.length > 0) {
        console.log(chalk.bold('🔝 Top Claims by Confidence'));
        console.log(chalk.gray('─'.repeat(50)));
        const sorted = [...data.claims].sort((a, b) => b.confidence - a.confidence).slice(0, 5);
        sorted.forEach((c, i) => {
            console.log(`  ${i + 1}. ${renderConfidenceBar(c.confidence)} ${chalk.cyan(c.subject)} ${chalk.gray(c.predicate)}`);
        });
        console.log();
    }

    // Artifact Types
    if (data.artifacts?.length > 0) {
        console.log(chalk.bold('📦 Artifacts by Type'));
        console.log(chalk.gray('─'.repeat(50)));
        const byType = {};
        data.artifacts.forEach(a => {
            byType[a.artifactType] = (byType[a.artifactType] || 0) + 1;
        });
        renderBarChart(byType);
    }
}

function showGraph(data) {
    console.log(chalk.bold.cyan('\n🕸️  KNOWLEDGE GRAPH (ASCII)\n'));

    if (!data.relations || data.relations.length === 0) {
        console.log(chalk.gray('  No relations in the model yet.'));
        return;
    }

    // Build adjacency for visualization
    const nodes = new Set();
    data.relations.forEach(r => {
        nodes.add(r.source);
        nodes.add(r.target);
    });

    console.log(chalk.gray(`  Nodes: ${nodes.size} | Edges: ${data.relations.length}\n`));

    // Simple ASCII representation
    data.relations.slice(0, 15).forEach(r => {
        const srcLabel = r.source.substring(0, 8);
        const tgtLabel = r.target.substring(0, 8);
        console.log(`  [${chalk.cyan(srcLabel)}] ──${chalk.yellow(r.type)}──▶ [${chalk.green(tgtLabel)}]`);
    });

    if (data.relations.length > 15) {
        console.log(chalk.gray(`  ... and ${data.relations.length - 15} more relations`));
    }
}

// Helper: Render ASCII bar chart
function renderBarChart(data) {
    const max = Math.max(...Object.values(data), 1);
    const barWidth = 30;

    Object.entries(data).forEach(([label, value]) => {
        const filled = Math.round((value / max) * barWidth);
        const bar = chalk.cyan('█'.repeat(filled)) + chalk.gray('░'.repeat(barWidth - filled));
        console.log(`  ${label.padEnd(18)} ${bar} ${value}`);
    });
}

// Helper: Render confidence as a colored bar
function renderConfidenceBar(confidence) {
    const width = 10;
    const filled = Math.round(confidence * width);
    let color = chalk.red;
    if (confidence >= 0.8) color = chalk.green;
    else if (confidence >= 0.5) color = chalk.yellow;

    const bar = color('█'.repeat(filled)) + chalk.gray('░'.repeat(width - filled));
    return `${bar} ${(confidence * 100).toFixed(0)}%`;
}

async function exportHtmlGraph(data, options) {
    const outputPath = options.output || path.join(options.workspace || '.', 'graph.html');
    const viewMode = options.view || 'topology';

    console.log(chalk.cyan(`  View mode: ${viewMode}`));

    let nodes, links;

    switch (viewMode) {
        case 'all':
            ({ nodes, links } = buildComprehensiveGraph(data));
            break;
        case 'evidence':
            ({ nodes, links } = buildEvidenceGraph(data));
            break;
        case 'provenance':
            ({ nodes, links } = buildProvenanceGraph(data));
            break;
        case 'topology':
        default:
            ({ nodes, links } = buildTopologyGraph(data));
            break;
    }

    const html = generateGraphHtml(nodes, links, data);
    await fs.writeFile(outputPath, html);

    console.log(chalk.green(`\n✅ Interactive graph exported to: ${outputPath}`));
    console.log(chalk.gray(`   Nodes: ${nodes.length}, Links: ${links.length}`));
    console.log(chalk.gray(`   Open in browser: file://${path.resolve(outputPath)}`));
}

function normalizeWorldModel(data) {
    // v2 state export: { evidence_graph, ledger, target_model, manifest, execution_log }
    if (data && data.evidence_graph && data.target_model && data.ledger) {
        const events = data.evidence_graph.events || [];
        const claims = data.ledger.claims || [];
        const entities = data.target_model.entities || [];
        const edges = data.target_model.edges || [];
        const manifestEntries = data.manifest?.entries || [];
        const executionLog = data.execution_log || data.executionLog || [];
        return { events, claims, entities, edges, manifestEntries, executionLog, format: 'v2' };
    }

    // legacy format (best-effort)
    return {
        events: data.evidence || [],
        claims: data.claims || [],
        entities: data.entities || [],
        edges: data.relations || [],
        manifestEntries: data.artifacts || [],
        executionLog: data.execution_log || data.executionLog || [],
        format: 'legacy',
    };
}

async function exportHtmlReview(data, options, workspace) {
    const outputPath = options.output || path.join(workspace || '.', 'model-review.html');

    const { events, claims, entities, edges, manifestEntries, executionLog, format } = normalizeWorldModel(data);

    const metricsPath = path.join(workspace || '.', 'deliverables', 'logs', 'metrics', 'metrics.json');
    let metrics = null;
    if (await fs.pathExists(metricsPath)) {
        try {
            metrics = await fs.readJSON(metricsPath);
        } catch {
            metrics = { error: 'Failed to parse metrics.json' };
        }
    }

    const html = generateReviewHtml({
        workspace,
        format,
        exportedAt: data.exported_at || data.exportedAt || null,
        events,
        claims,
        entities,
        edges,
        manifestEntries,
        executionLog,
        metrics,
    });

    await fs.writeFile(outputPath, html);

    console.log(chalk.green(`\n✅ Model review exported to: ${outputPath}`));
    console.log(chalk.gray(`   Open in browser: file://${path.resolve(outputPath)}`));
}

async function exportProxyBundle(data, options, workspace) {
    const workspaceRoot = path.resolve(workspace || '.');
    const outputDir = resolveOutputDir(options.output, workspaceRoot);
    const { events, entities } = normalizeWorldModel(data);

    await fs.ensureDir(outputDir);

    const endpointList = collectEndpoints(entities, events);
    const openapiSource = await writeOpenApiBundle({
        workspaceRoot,
        outputDir,
        endpoints: endpointList,
        baseUrlOverride: options.target,
    });

    const baseUrl = openapiSource.baseUrl;
    const urls = buildUrlList(endpointList, baseUrl);
    const urlsPath = path.join(outputDir, 'urls.txt');
    await fs.writeFile(urlsPath, urls.join('\n') + (urls.length ? '\n' : ''));

    const targetsPath = path.join(outputDir, 'targets.txt');
    const targets = baseUrl ? [baseUrl] : [];
    if (targets.length > 0) {
        await fs.writeFile(targetsPath, targets.join('\n') + '\n');
    }

    const bundleMetaPath = path.join(outputDir, 'proxy-bundle.json');
    await fs.writeJSON(bundleMetaPath, {
        created_at: new Date().toISOString(),
        base_url: baseUrl || null,
        endpoints: endpointList.length,
        urls: urls.length,
        openapi_source: openapiSource.kind,
    }, { spaces: 2 });

    const readmePath = path.join(outputDir, 'README.md');
    await fs.writeFile(readmePath, buildProxyReadme({
        baseUrl,
        openapiSource: openapiSource.kind,
        endpoints: endpointList.length,
        urls: urls.length,
    }));

    console.log(chalk.green(`\n✅ Proxy bundle exported to: ${outputDir}`));
    console.log(chalk.gray(`   OpenAPI: ${path.join(outputDir, 'openapi.json')} (${openapiSource.kind})`));
    console.log(chalk.gray(`   URLs: ${urlsPath} (${urls.length})`));
    if (baseUrl) {
        console.log(chalk.gray(`   Base URL: ${baseUrl}`));
    } else {
        console.log(chalk.yellow('   Base URL: not inferred (urls.txt contains paths only)'));
    }
}

function resolveOutputDir(output, workspaceRoot) {
    if (!output) {
        return path.join(workspaceRoot, 'deliverables', 'proxy');
    }
    return path.isAbsolute(output) ? output : path.join(workspaceRoot, output);
}

function collectEndpoints(entities = [], events = []) {
    const endpoints = new Map();
    const addEndpoint = (entry) => {
        if (!entry || !entry.path) return;
        const method = normalizeMethod(entry.method);
        const pathValue = normalizePath(entry.path);
        const key = `${method} ${pathValue}`;

        if (!endpoints.has(key)) {
            endpoints.set(key, {
                method,
                path: pathValue,
                url: entry.url || null,
                params: [],
            });
        }

        const target = endpoints.get(key);
        if (entry.url && !target.url) {
            target.url = entry.url;
        }
        mergeParams(target.params, entry.params || []);
    };

    for (const entity of entities || []) {
        if (entity?.entity_type !== 'endpoint') continue;
        const attrs = entity.attributes || {};
        addEndpoint({
            method: attrs.method || attrs.http_method,
            path: attrs.path || attrs.url,
            url: attrs.url,
            params: Array.isArray(attrs.params) ? attrs.params : [],
        });
    }

    for (const event of events || []) {
        const payload = event.payload || event.content || {};
        const eventType = event.event_type || event.type || payload.type || '';
        const isEndpoint = eventType === 'endpoint_discovered'
            || eventType === 'api_endpoint_inferred'
            || payload.type === 'endpoint';

        if (!isEndpoint && !payload.path && !payload.url) continue;

        const urlValue = typeof payload.url === 'string' ? payload.url : null;
        const pathValue = payload.path || (urlValue ? safeUrlPath(urlValue) : null);
        addEndpoint({
            method: payload.method || payload.http_method || payload.httpMethod,
            path: pathValue,
            url: urlValue,
            params: Array.isArray(payload.params) ? payload.params : extractQueryParams(urlValue),
        });
    }

    return Array.from(endpoints.values());
}

function normalizeMethod(value) {
    return (value || 'GET').toString().toUpperCase();
}

function normalizePath(pathValue) {
    if (!pathValue) return '/';
    let normalized = pathValue.toString().trim();
    if (/^https?:\/\//i.test(normalized)) {
        const parsed = safeUrlPath(normalized);
        if (parsed) {
            normalized = parsed;
        }
    }
    if (normalized.includes('?')) {
        normalized = normalized.split('?')[0];
    }
    if (normalized.includes('#')) {
        normalized = normalized.split('#')[0];
    }
    if (!normalized.startsWith('/')) {
        normalized = `/${normalized}`;
    }
    normalized = normalized.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
    return normalized;
}

function safeUrlPath(urlValue) {
    if (!urlValue) return null;
    try {
        return new URL(urlValue).pathname || '/';
    } catch {
        return null;
    }
}

function extractQueryParams(urlValue) {
    if (!urlValue) return [];
    try {
        const url = new URL(urlValue);
        const params = [];
        for (const name of url.searchParams.keys()) {
            params.push({ name, location: 'query', type: 'string' });
        }
        return params;
    } catch {
        return [];
    }
}

function mergeParams(targetParams, incoming) {
    if (!Array.isArray(targetParams) || !Array.isArray(incoming)) return;
    for (const param of incoming) {
        if (!param || !param.name) continue;
        const location = param.location || param.in || 'query';
        const exists = targetParams.some(p => p.name === param.name && (p.location || p.in || 'query') === location);
        if (!exists) {
            targetParams.push({
                name: param.name,
                location,
                type: param.type || 'string',
            });
        }
    }
}

function buildUrlList(endpoints, baseUrl) {
    const urls = new Set();
    for (const endpoint of endpoints) {
        const urlValue = endpoint.url || (baseUrl ? safeJoinUrl(baseUrl, endpoint.path) : null);
        if (urlValue) {
            urls.add(urlValue);
        } else if (endpoint.path) {
            urls.add(endpoint.path);
        }
    }
    return Array.from(urls).sort();
}

function safeJoinUrl(baseUrl, pathValue) {
    try {
        return new URL(pathValue, baseUrl).toString();
    } catch {
        return null;
    }
}

async function writeOpenApiBundle({ workspaceRoot, outputDir, endpoints, baseUrlOverride }) {
    const workspaceOpenApiPath = path.join(workspaceRoot, 'openapi.json');
    const outputOpenApiPath = path.join(outputDir, 'openapi.json');
    let openapi = null;
    let baseUrl = normalizeBaseUrl(baseUrlOverride);
    let kind = 'generated';
    let copied = false;

    if (await fs.pathExists(workspaceOpenApiPath)) {
        const raw = await fs.readFile(workspaceOpenApiPath, 'utf-8');
        await fs.writeFile(outputOpenApiPath, raw);
        kind = 'copied';
        copied = true;
        try {
            openapi = JSON.parse(raw);
        } catch {
            openapi = null;
        }
    }

    if (!baseUrl && openapi?.servers?.length) {
        baseUrl = normalizeBaseUrl(openapi.servers[0]?.url);
    }

    if (!baseUrl) {
        baseUrl = inferBaseUrlFromEndpoints(endpoints);
    }

    if (!copied) {
        openapi = buildOpenApiSpec(endpoints, baseUrl);
        await fs.writeJSON(outputOpenApiPath, openapi, { spaces: 2 });
    }

    return { kind, baseUrl };
}

function inferBaseUrlFromEndpoints(endpoints) {
    for (const endpoint of endpoints || []) {
        if (!endpoint?.url) continue;
        const base = normalizeBaseUrl(endpoint.url);
        if (base) return base;
    }
    return null;
}

function normalizeBaseUrl(value) {
    if (!value || typeof value !== 'string') return null;
    try {
        return new URL(value).origin;
    } catch {
        try {
            return new URL(`https://${value}`).origin;
        } catch {
            return null;
        }
    }
}

function buildOpenApiSpec(endpoints, baseUrl) {
    const title = baseUrl ? `${new URL(baseUrl).hostname} API` : 'Discovered API';
    const spec = {
        openapi: '3.0.3',
        info: {
            title,
            version: '1.0.0',
            description: 'Auto-generated OpenAPI spec from Shannon endpoints',
            'x-shannon-generated': true,
        },
        servers: baseUrl ? [{ url: baseUrl, description: 'Target server' }] : [],
        paths: {},
        components: {
            schemas: {},
        },
    };

    for (const endpoint of endpoints) {
        if (!endpoint.path) continue;
        const method = (endpoint.method || 'GET').toLowerCase();
        if (!spec.paths[endpoint.path]) {
            spec.paths[endpoint.path] = {};
        }
        if (spec.paths[endpoint.path][method]) continue;

        const { params, bodyParams } = splitParams(endpoint);

        const operation = {
            summary: `${method.toUpperCase()} ${endpoint.path}`,
            responses: {
                '200': {
                    description: 'Successful response',
                },
            },
        };

        if (params.length > 0) {
            operation.parameters = params.map(param => ({
                name: param.name,
                in: param.location || 'query',
                required: param.location === 'path',
                schema: { type: mapParamType(param.type) },
            }));
        }

        if (bodyParams.length > 0 && ['post', 'put', 'patch'].includes(method)) {
            const properties = {};
            for (const param of bodyParams) {
                properties[param.name] = { type: mapParamType(param.type) };
            }
            operation.requestBody = {
                required: true,
                content: {
                    'application/json': {
                        schema: {
                            type: 'object',
                            properties,
                        },
                    },
                },
            };
        }

        spec.paths[endpoint.path][method] = operation;
    }

    return spec;
}

function splitParams(endpoint) {
    const params = [];
    const bodyParams = [];
    const seen = new Set();

    const pathParams = extractPathParams(endpoint.path);
    for (const name of pathParams) {
        if (!seen.has(`path:${name}`)) {
            params.push({ name, location: 'path', type: 'string' });
            seen.add(`path:${name}`);
        }
    }

    for (const param of endpoint.params || []) {
        if (!param || !param.name) continue;
        const location = param.location || param.in || 'query';
        const key = `${location}:${param.name}`;
        if (seen.has(key)) continue;
        if (location === 'body') {
            bodyParams.push(param);
        } else {
            params.push({ name: param.name, location, type: param.type || 'string' });
        }
        seen.add(key);
    }

    return { params, bodyParams };
}

function extractPathParams(pathValue) {
    if (!pathValue) return [];
    const params = [];
    const matches = pathValue.matchAll(/{([^}]+)}/g);
    for (const match of matches) {
        if (match[1]) {
            params.push(match[1]);
        }
    }
    return params;
}

function mapParamType(type) {
    const typeMap = {
        string: 'string',
        integer: 'integer',
        number: 'number',
        boolean: 'boolean',
        array: 'array',
        object: 'object',
        uuid: 'string',
        email: 'string',
        date: 'string',
    };
    return typeMap[type] || 'string';
}

function buildProxyReadme({ baseUrl, openapiSource, endpoints, urls }) {
    const lines = [
        '# Proxy Export Bundle',
        '',
        'Generated files:',
        '- openapi.json: OpenAPI spec for ZAP/Burp import.',
        '- urls.txt: URL list for proxy seeding (one URL per line).',
        '- targets.txt: Base URL hint used for URL expansion (when inferred).',
        '- proxy-bundle.json: Bundle metadata.',
        '',
        'Notes:',
        `- OpenAPI source: ${openapiSource}.`,
        `- Base URL: ${baseUrl || 'not inferred'}.`,
        `- Endpoints: ${endpoints}.`,
        `- URLs: ${urls}.`,
        '',
        'Usage hints:',
        '- ZAP: File -> Import -> OpenAPI definition, or Import URLs from file.',
        '- Burp: use OpenAPI import (if available) or add hosts/paths from urls.txt.',
        '',
    ];
    return lines.join('\n');
}

function generateReviewHtml(payload) {
    // Embed JSON for offline use (no fetch/CORS issues).
    const json = JSON.stringify(payload).replace(/</g, '\\u003c');

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Shannon Model Review</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#0b0f14; color:#e6edf3; }
    header { padding: 16px 18px; border-bottom: 1px solid #233041; background: #0b0f14; position: sticky; top: 0; z-index: 10; }
    h1 { font-size: 16px; margin: 0 0 6px 0; }
    .sub { font-size: 12px; color: #9fb0c0; display:flex; gap:14px; flex-wrap:wrap; }
    .wrap { display: grid; grid-template-columns: 260px 1fr; min-height: calc(100vh - 60px); }
    nav { border-right: 1px solid #233041; padding: 12px; background:#0c121a; }
    nav button { width: 100%; text-align: left; padding: 10px 10px; border-radius: 10px; border: 1px solid transparent; background: transparent; color:#e6edf3; cursor: pointer; }
    nav button.active { background:#111a24; border-color:#233041; }
    main { padding: 16px; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; margin-bottom: 14px; }
    .card { border: 1px solid #233041; background:#0c121a; border-radius: 14px; padding: 12px; }
    .k { font-size: 12px; color:#9fb0c0; }
    .v { font-size: 18px; margin-top: 4px; }
    .row { display:flex; gap: 10px; align-items:center; flex-wrap: wrap; margin: 8px 0 12px; }
    input[type="search"] { width: min(680px, 100%); padding: 10px 12px; border-radius: 12px; border: 1px solid #233041; background:#0b0f14; color:#e6edf3; }
    table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 12px; border: 1px solid #233041; }
    th, td { padding: 10px 10px; border-bottom: 1px solid #233041; font-size: 12px; vertical-align: top; }
    th { text-align: left; background: #0c121a; color:#cbd7e3; position: sticky; top: 0; z-index: 1; }
    tr:hover td { background: #0f1722; }
    code { color: #d2a8ff; }
    .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid #233041; background:#0b0f14; color:#cbd7e3; font-size: 11px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
    .muted { color:#9fb0c0; }
    .err { color:#ff7b72; }
  </style>
</head>
<body>
  <header>
    <h1>Shannon Model Review</h1>
    <div class="sub">
      <span>Workspace: <span class="mono">${escapeHtml(String(payload.workspace || ''))}</span></span>
      <span>Format: <span class="pill">${escapeHtml(String(payload.format))}</span></span>
      <span>Exported: <span class="mono">${escapeHtml(String(payload.exportedAt || 'unknown'))}</span></span>
    </div>
  </header>

  <div class="wrap">
    <nav>
      <button data-view="summary" class="active">Summary</button>
      <button data-view="execution">Execution Log</button>
      <button data-view="entities">Entities</button>
      <button data-view="edges">Edges</button>
      <button data-view="claims">Claims</button>
      <button data-view="events">Evidence Events</button>
      <button data-view="metrics">Metrics</button>
      <button data-view="raw">Raw JSON</button>
    </nav>
    <main>
      <div id="view"></div>
    </main>
  </div>

  <script>
    const DATA = ${json};

    function esc(s){ return String(s ?? '').replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c])); }
    function fmt(n){ return new Intl.NumberFormat().format(n); }

    const viewEl = document.getElementById('view');
    const buttons = Array.from(document.querySelectorAll('nav button'));
    buttons.forEach(b => b.addEventListener('click', () => {
      buttons.forEach(x => x.classList.toggle('active', x === b));
      render(b.dataset.view);
    }));

    function summaryCards(){
      const ok = (DATA.executionLog || []).filter(e => e && e.success === true).length;
      const fail = (DATA.executionLog || []).filter(e => e && e.success === false).length;
      return [
        { k: 'Evidence events', v: (DATA.events || []).length },
        { k: 'Claims', v: (DATA.claims || []).length },
        { k: 'Entities', v: (DATA.entities || []).length },
        { k: 'Edges', v: (DATA.edges || []).length },
        { k: 'Manifest entries', v: (DATA.manifestEntries || []).length },
        { k: 'Agents OK', v: ok },
        { k: 'Agents failed', v: fail },
        { k: 'Metrics present', v: DATA.metrics ? 'yes' : 'no' },
      ];
    }

    function renderTable(rows, columns, opts = {}){
      const id = opts.id || 't';
      const search = opts.search !== false;
      const placeholder = opts.placeholder || 'Filter...';

      let html = '';
      if (search) {
        html += '<div class="row"><input id="'+id+'_q" type="search" placeholder="'+esc(placeholder)+'" /></div>';
      }
      html += '<div style="overflow:auto; max-height: calc(100vh - 190px);">';
      html += '<table><thead><tr>' + columns.map(c => '<th>'+esc(c.label)+'</th>').join('') + '</tr></thead><tbody id="'+id+'_body"></tbody></table>';
      html += '</div>';
      viewEl.innerHTML = html;

      const body = document.getElementById(id+'_body');
      const q = search ? document.getElementById(id+'_q') : null;

      const renderRows = (query) => {
        const ql = String(query || '').toLowerCase().trim();
        const filtered = ql ? rows.filter(r => JSON.stringify(r).toLowerCase().includes(ql)) : rows;
        body.innerHTML = filtered.slice(0, 2000).map(r => {
          return '<tr>' + columns.map(c => {
            const val = c.get(r);
            if (c.pre) return '<td class="mono"><pre>'+esc(val)+'</pre></td>';
            return '<td>'+esc(val)+'</td>';
          }).join('') + '</tr>';
        }).join('');
      };

      if (q) {
        q.addEventListener('input', () => renderRows(q.value));
      }
      renderRows('');
    }

    function render(view){
      if (view === 'summary') {
        const cards = summaryCards();
        viewEl.innerHTML = '<div class="grid">' + cards.map(c => '<div class="card"><div class="k">'+esc(c.k)+'</div><div class="v">'+esc(typeof c.v === 'number' ? fmt(c.v) : c.v)+'</div></div>').join('') + '</div>' +
          '<div class="card"><div class="k">Notes</div><div class="muted" style="margin-top:6px;">This page embeds the model + metrics for offline review. Tables cap at 2,000 rows for responsiveness.</div></div>';
        return;
      }

      if (view === 'execution') {
        const rows = (DATA.executionLog || []).map(e => ({
          agent: e.agent,
          timestamp: e.timestamp,
          success: e.success,
          error: e.error || '',
          duration_ms: e.summary?.duration_ms ?? '',
          tools: e.summary?.tool_invocations ?? '',
          net: e.summary?.network_requests ?? '',
        }));
        renderTable(rows, [
          { label: 'Agent', get: r => r.agent },
          { label: 'Time', get: r => r.timestamp },
          { label: 'Success', get: r => String(r.success) },
          { label: 'Error', get: r => r.error },
          { label: 'Duration (ms)', get: r => String(r.duration_ms) },
          { label: 'Tools', get: r => String(r.tools) },
          { label: 'Net', get: r => String(r.net) },
        ], { id: 'exec', placeholder: 'Filter execution log...' });
        return;
      }

      if (view === 'entities') {
        renderTable(DATA.entities || [], [
          { label: 'ID', get: r => r.id },
          { label: 'Type', get: r => r.entity_type || r.type || '' },
          { label: 'Attrs', get: r => JSON.stringify(r.attributes || {}, null, 2), pre: true },
        ], { id: 'entities', placeholder: 'Filter entities...' });
        return;
      }

      if (view === 'edges') {
        renderTable(DATA.edges || [], [
          { label: 'Source', get: r => r.source },
          { label: 'Relationship', get: r => r.relationship || r.type || '' },
          { label: 'Target', get: r => r.target },
          { label: 'Claims', get: r => JSON.stringify(r.claim_refs || r.claim_refs || []), pre: false },
        ], { id: 'edges', placeholder: 'Filter edges...' });
        return;
      }

      if (view === 'claims') {
        renderTable(DATA.claims || [], [
          { label: 'ID', get: r => r.id || '' },
          { label: 'Type', get: r => r.claim_type || r.type || '' },
          { label: 'Subject', get: r => r.subject || '' },
          { label: 'Predicate', get: r => JSON.stringify(r.predicate || {}, null, 2), pre: true },
          { label: 'EBSL/EQBSL', get: r => JSON.stringify(r.eqbsl || r.opinion || {}, null, 2), pre: true },
        ], { id: 'claims', placeholder: 'Filter claims...' });
        return;
      }

      if (view === 'events') {
        renderTable(DATA.events || [], [
          { label: 'ID', get: r => r.id || '' },
          { label: 'Type', get: r => r.event_type || r.type || '' },
          { label: 'Source', get: r => r.source || r.source_agent || '' },
          { label: 'Time', get: r => r.timestamp || '' },
          { label: 'Payload', get: r => JSON.stringify(r.payload || r.content || r.data || {}, null, 2), pre: true },
        ], { id: 'events', placeholder: 'Filter evidence events...' });
        return;
      }

      if (view === 'metrics') {
        const m = DATA.metrics;
        if (!m) {
          viewEl.innerHTML = '<div class="card"><div class="k">Metrics</div><div class="muted" style="margin-top:6px;">No metrics found at <span class="mono">deliverables/logs/metrics/metrics.json</span>.</div></div>';
          return;
        }
        viewEl.innerHTML =
          '<div class="card"><div class="k">Metrics JSON</div><div class="muted" style="margin-top:6px;">Raw metrics as produced by the run.</div></div>' +
          '<div class="card" style="margin-top:12px;"><pre class="mono">'+esc(JSON.stringify(m, null, 2))+'</pre></div>';
        return;
      }

      if (view === 'raw') {
        viewEl.innerHTML = '<div class="card"><pre class="mono">'+esc(JSON.stringify(DATA, null, 2))+'</pre></div>';
        return;
      }

      viewEl.innerHTML = '<div class="card"><div class="k">Unknown view</div><div class="muted">'+esc(view)+'</div></div>';
    }

    render('summary');
  </script>
</body>
</html>`;
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

// === GRAPH BUILDERS ===

// === COMPREHENSIVE GRAPH ===
// Merges all views: agents, evidence, ports, tech, domains, event types, targets
function buildComprehensiveGraph(data) {
    const nodesMap = new Map();
    const links = [];

    // --- 1. AGENTS ---
    const agents = new Set();
    data.evidence?.forEach(e => agents.add(e.sourceAgent));

    agents.forEach(agent => {
        nodesMap.set(`agent_${agent}`, {
            id: `agent_${agent}`,
            label: agent,
            type: 'agent',
            eqbsl: { b: 0.85, d: 0.03, u: 0.12, a: 0.5 }
        });
    });

    // --- 2. EVENT TYPES ---
    const eventTypes = new Map();
    data.evidence?.forEach(e => {
        const eventType = e.content?.type || e.content?.tool || 'observation';
        if (!eventTypes.has(eventType)) {
            eventTypes.set(eventType, {
                id: `eventType_${eventType}`,
                label: eventType.toUpperCase(),
                type: 'eventType',
                count: 0,
                eqbsl: { b: 0.7, d: 0.1, u: 0.2, a: 0.5 }
            });
        }
        eventTypes.get(eventType).count++;
    });
    eventTypes.forEach(node => nodesMap.set(node.id, node));

    // Link agents to event types they produce
    const agentEventLinks = new Set();
    data.evidence?.forEach(e => {
        const eventType = e.content?.type || e.content?.tool || 'observation';
        const linkKey = `agent_${e.sourceAgent}->eventType_${eventType}`;
        if (!agentEventLinks.has(linkKey)) {
            agentEventLinks.add(linkKey);
            links.push({
                source: `agent_${e.sourceAgent}`,
                target: `eventType_${eventType}`,
                type: 'emits',
                eqbsl: { b: 0.8, d: 0.05, u: 0.15, a: 0.5 }
            });
        }
    });

    // --- 3. DOMAINS (from subdomains) ---
    const subdomainEvidence = data.evidence?.find(e => e.content?.tool === 'subfinder');
    const subdomains = subdomainEvidence?.content?.subdomains || [];

    const domainHubs = new Map();
    subdomains.forEach(sub => {
        const prefix = sub.split('.')[0];
        if (!domainHubs.has(prefix) && prefix.length > 2) {
            domainHubs.set(prefix, {
                id: `domain_${prefix}`,
                label: prefix,
                type: 'domain',
                fullDomain: sub,
                eqbsl: { b: 0.75, d: 0.05, u: 0.2, a: 0.5 }
            });
        }
    });
    domainHubs.forEach(node => nodesMap.set(node.id, node));

    // Link subfinder event type to domains
    if (eventTypes.has('subfinder') && domainHubs.size > 0) {
        domainHubs.forEach((_, prefix) => {
            links.push({
                source: 'eventType_subfinder',
                target: `domain_${prefix}`,
                type: 'discovered',
                eqbsl: { b: 0.85, d: 0.03, u: 0.12, a: 0.5 }
            });
        });
    }

    // --- 4. PORTS (from nmap) ---
    const nmapEvidence = data.evidence?.find(e => e.content?.tool === 'nmap');
    if (nmapEvidence) {
        const nmapResult = nmapEvidence.content?.result || '';
        const ports = nmapResult.match(/(\d+)\/tcp\s+open\s+(\S+)/g) || [];

        ports.forEach(portLine => {
            const match = portLine.match(/(\d+)\/tcp\s+open\s+(\S+)/);
            if (match) {
                const [, port, service] = match;
                const portNodeId = `port_${port}`;

                nodesMap.set(portNodeId, {
                    id: portNodeId,
                    label: `${port}/${service}`,
                    type: 'port',
                    eqbsl: { b: 0.95, d: 0.01, u: 0.04, a: 0.5 }
                });

                // Link nmap event type to port
                if (eventTypes.has('nmap')) {
                    links.push({
                        source: 'eventType_nmap',
                        target: portNodeId,
                        type: 'discovered',
                        eqbsl: { b: 0.98, d: 0.0, u: 0.02, a: 0.5 }
                    });
                }
            }
        });
    }

    // --- 5. TARGETS (path categories from endpoints) ---
    const pathCategories = new Map();
    data.evidence?.forEach(e => {
        if (e.content?.path) {
            const parts = e.content.path.split('/').filter(p => p);
            if (parts.length > 0) {
                const category = parts[0];
                if (!pathCategories.has(category)) {
                    pathCategories.set(category, {
                        id: `target_${category}`,
                        label: `/${category}`,
                        type: 'target',
                        count: 0,
                        eqbsl: { b: 0.6, d: 0.1, u: 0.3, a: 0.5 }
                    });
                }
                pathCategories.get(category).count++;
            }
        }
    });

    // Only add top path categories (>= 3 occurrences)
    pathCategories.forEach((node, key) => {
        if (node.count >= 3) {
            nodesMap.set(node.id, node);

            // Link endpoint event type to target
            if (eventTypes.has('endpoint')) {
                links.push({
                    source: 'eventType_endpoint',
                    target: node.id,
                    type: 'reaches',
                    eqbsl: { b: 0.65, d: 0.1, u: 0.25, a: 0.5 }
                });
            }
        }
    });

    // --- 6. CLAIMS (from world model claims) ---
    data.claims?.slice(0, 50).forEach(claim => {
        const claimId = `claim_${claim.id || claim.subject}`;
        nodesMap.set(claimId, {
            id: claimId,
            label: claim.predicate ? `${claim.subject}:${claim.predicate}`.substring(0, 25) : claim.subject.substring(0, 25),
            type: 'claim',
            confidence: claim.confidence,
            eqbsl: claim.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 }
        });

        // Link claim to its supporting evidence (if evidence is an agent)
        if (claim.evidenceIds?.length > 0) {
            // Find which agent produced the first evidence
            const firstEvId = claim.evidenceIds[0];
            const ev = data.evidence?.find(e => e.id === firstEvId);
            if (ev && nodesMap.has(`agent_${ev.sourceAgent}`)) {
                links.push({
                    source: `agent_${ev.sourceAgent}`,
                    target: claimId,
                    type: 'claims',
                    eqbsl: claim.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 }
                });
            }
        }
    });

    // Calculate EQBSL properties for all links
    links.forEach(link => {
        const eqbsl = link.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 };
        link.expectation = eqbsl.b + (eqbsl.a * eqbsl.u);
        link.controversy = eqbsl.b * eqbsl.d;
        link.uncertainty = eqbsl.u;
    });

    return { nodes: Array.from(nodesMap.values()), links };
}

function buildTopologyGraph(data) {
    const nodesMap = new Map();
    const links = [];

    // === BUILD A REAL NETWORK TOPOLOGY ===

    // 1. Create DOMAIN hub nodes from subdomains in evidence
    const subdomainEvidence = data.evidence?.find(e => e.content?.tool === 'subfinder');
    const subdomains = subdomainEvidence?.content?.subdomains || [];

    // Extract unique base subdomains (e.g., "api", "auth", "dashboard")
    const domainHubs = new Map();
    subdomains.forEach(sub => {
        const prefix = sub.split('.')[0]; // Get first part like "api", "auth"
        if (!domainHubs.has(prefix)) {
            domainHubs.set(prefix, {
                id: `hub_${prefix}`,
                label: prefix,
                type: 'domain',
                fullDomain: sub,
                eqbsl: { b: 0.6, d: 0.1, u: 0.3, a: 0.5 }
            });
        }
    });

    // Add domain hubs as nodes
    domainHubs.forEach((node, key) => nodesMap.set(node.id, node));

    // 2. Create PATH CATEGORY nodes from endpoint patterns
    const pathCategories = new Map();
    data.evidence?.filter(e => e.content?.type === 'endpoint').forEach(e => {
        const path = e.content?.path || '/';
        const parts = path.split('/').filter(p => p && !p.includes('.') && !p.includes('%'));

        // Create category for first path segment
        if (parts.length > 0) {
            const category = parts[0];
            if (!pathCategories.has(category)) {
                pathCategories.set(category, {
                    id: `path_${category}`,
                    label: `/${category}`,
                    type: 'pathCategory',
                    count: 0,
                    eqbsl: { b: 0.5, d: 0.15, u: 0.35, a: 0.5 }
                });
            }
            pathCategories.get(category).count++;
        }
    });

    // Only keep categories with multiple endpoints
    pathCategories.forEach((node, key) => {
        if (node.count >= 3) {
            nodesMap.set(node.id, node);
        }
    });

    // 3. Create TOOL nodes for reconnaissance tools
    const toolNodes = ['nmap', 'subfinder', 'whatweb'].map(tool => ({
        id: `tool_${tool}`,
        label: tool.toUpperCase(),
        type: 'tool',
        eqbsl: { b: 0.8, d: 0.05, u: 0.15, a: 0.5 }
    }));
    toolNodes.forEach(n => nodesMap.set(n.id, n));

    // 4. Create connections: Tools → Domain hubs (discovered by)
    domainHubs.forEach((hub, prefix) => {
        links.push({
            source: 'tool_subfinder',
            target: hub.id,
            type: 'discovered',
            eqbsl: { b: 0.7, d: 0.1, u: 0.2, a: 0.5 }
        });
    });

    // 5. Connect domain hubs to path categories based on endpoint sources
    data.evidence?.filter(e => e.content?.type === 'endpoint').slice(0, 500).forEach(e => {
        const source = e.content?.source || '';
        const path = e.content?.path || '/';
        const parts = path.split('/').filter(p => p && !p.includes('.') && !p.includes('%'));

        if (parts.length > 0) {
            const category = `path_${parts[0]}`;

            // Find which subdomain this endpoint belongs to
            for (const [prefix, hub] of domainHubs) {
                if (source.includes(`${prefix}.`) || source.includes(`${prefix}-`)) {
                    if (nodesMap.has(category)) {
                        // Add link if it doesn't exist
                        const linkKey = `${hub.id}->${category}`;
                        if (!links.find(l => `${l.source}->${l.target}` === linkKey)) {
                            links.push({
                                source: hub.id,
                                target: category,
                                type: 'hosts',
                                eqbsl: { b: 0.6, d: 0.1, u: 0.3, a: 0.5 }
                            });
                        }
                    }
                    break;
                }
            }
        }
    });

    // 6. Connect path categories that share structure
    const categories = Array.from(pathCategories.values()).filter(c => c.count >= 3);
    for (let i = 0; i < categories.length; i++) {
        for (let j = i + 1; j < categories.length; j++) {
            // Connect if both have high count (related areas)
            if (categories[i].count > 5 && categories[j].count > 5) {
                links.push({
                    source: categories[i].id,
                    target: categories[j].id,
                    type: 'related',
                    eqbsl: { b: 0.3, d: 0.2, u: 0.5, a: 0.5 }
                });
            }
        }
    }

    // 7. Add port/service nodes from nmap
    const nmapEvidence = data.evidence?.find(e => e.content?.tool === 'nmap');
    if (nmapEvidence) {
        const nmapResult = nmapEvidence.content?.result || '';
        const ports = nmapResult.match(/(\d+)\/tcp\s+open\s+(\S+)/g) || [];

        ports.forEach(portLine => {
            const match = portLine.match(/(\d+)\/tcp\s+open\s+(\S+)/);
            if (match) {
                const [, port, service] = match;
                const portNode = {
                    id: `port_${port}`,
                    label: `${port}/${service}`,
                    type: 'port',
                    eqbsl: { b: 0.9, d: 0.02, u: 0.08, a: 0.5 }
                };
                nodesMap.set(portNode.id, portNode);
                links.push({
                    source: 'tool_nmap',
                    target: portNode.id,
                    type: 'discovered',
                    eqbsl: { b: 0.95, d: 0.01, u: 0.04, a: 0.5 }
                });
            }
        });
    }

    // Calculate EQBSL properties for all links
    links.forEach(link => {
        const eqbsl = link.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 };
        link.expectation = eqbsl.b + (eqbsl.a * eqbsl.u);
        link.controversy = eqbsl.b * eqbsl.d;
        link.uncertainty = eqbsl.u;
    });

    return { nodes: Array.from(nodesMap.values()), links };
}

// === EVIDENCE GRAPH ===
// Shows evidence items grouped by sourceAgent with connections to what they discovered
function buildEvidenceGraph(data) {
    const nodesMap = new Map();
    const links = [];

    // Create agent nodes
    const agents = new Set();
    data.evidence?.forEach(e => agents.add(e.sourceAgent));

    agents.forEach(agent => {
        nodesMap.set(`agent_${agent}`, {
            id: `agent_${agent}`,
            label: agent,
            type: 'agent',
            eqbsl: { b: 0.8, d: 0.05, u: 0.15, a: 0.5 }
        });
    });

    // Create evidence nodes and link to agents
    data.evidence?.slice(0, 300).forEach((e, i) => {
        const label = e.content?.path || e.content?.tool || e.content?.type || `ev_${i}`;
        nodesMap.set(e.id, {
            id: e.id,
            label: label.substring(0, 30),
            type: 'evidence',
            agent: e.sourceAgent,
            fullContent: e.content,
            eqbsl: e.eqbsl || { b: 0.5, d: 0.1, u: 0.4, a: 0.5 }
        });

        // Link evidence to its agent
        links.push({
            source: `agent_${e.sourceAgent}`,
            target: e.id,
            type: 'produced',
            eqbsl: { b: 0.9, d: 0.02, u: 0.08, a: 0.5 }
        });

        // --- ENHANCEMENT: Parse content for deeper nodes ---

        // 1. Nmap Ports
        if (e.content?.tool === 'nmap' && e.content.result) {
            const ports = e.content.result.match(/(\d+)\/tcp\s+open\s+(\S+)/g) || [];
            ports.forEach(portLine => {
                const match = portLine.match(/(\d+)\/tcp\s+open\s+(\S+)/);
                if (match) {
                    const [, port, service] = match;
                    const portNodeId = `port_${port}_${e.id.substring(0, 8)}`; // Unique per scan

                    if (!nodesMap.has(portNodeId)) {
                        nodesMap.set(portNodeId, {
                            id: portNodeId,
                            label: `${port}/${service}`,
                            type: 'port',
                            eqbsl: { b: 0.95, d: 0.01, u: 0.04, a: 0.5 }
                        });
                    }

                    links.push({
                        source: e.id,
                        target: portNodeId,
                        type: 'reveals',
                        eqbsl: { b: 0.99, d: 0.0, u: 0.01, a: 0.5 }
                    });
                }
            });
        }

        // 2. WhatWeb Tech
        if (e.content?.tool === 'whatweb' && e.content.result) {
            // Extract plugins/tech from whatweb output (simplified parsing)
            // Example: [ 200 OK ] Apache[2.4.41], Country[UNITED STATES][US], HTTPServer[Ubuntu Linux][Apache/2.4.41]
            const techMatches = e.content.result.match(/([a-zA-Z0-9_\-]+)\[(.*?)\]/g) || [];
            techMatches.slice(0, 8).forEach(tm => { // Limit to top 8 to avoid noise
                const parts = tm.match(/([a-zA-Z0-9_\-]+)\[(.*?)\]/);
                if (parts) {
                    const name = parts[1];
                    // Skip boring ones
                    if (['Country', 'IP', 'Title', 'HTTPServer'].includes(name)) return;

                    const techId = `tech_${name}_${e.id.substring(0, 8)}`;

                    if (!nodesMap.has(techId)) {
                        nodesMap.set(techId, {
                            id: techId,
                            label: name,
                            type: 'claim', // Reusing claim color for tech/findings
                            eqbsl: { b: 0.8, d: 0.1, u: 0.1, a: 0.5 }
                        });
                    }

                    links.push({
                        source: e.id,
                        target: techId,
                        type: 'detects',
                        eqbsl: { b: 0.8, d: 0.1, u: 0.1, a: 0.5 }
                    });
                }
            });
        }
    });

    // Connect evidence that share content similarities
    const evidenceByType = new Map();
    data.evidence?.slice(0, 300).forEach(e => {
        const type = e.content?.type || e.content?.tool || 'other';
        if (!evidenceByType.has(type)) evidenceByType.set(type, []);
        evidenceByType.get(type).push(e.id);
    });

    // Link evidence of same type (sampled)
    evidenceByType.forEach((ids, type) => {
        if (ids.length > 1 && ids.length < 20) {
            for (let i = 0; i < Math.min(ids.length - 1, 5); i++) {
                links.push({
                    source: ids[i],
                    target: ids[i + 1],
                    type: 'related',
                    eqbsl: { b: 0.4, d: 0.2, u: 0.4, a: 0.5 }
                });
            }
        }
    });

    // Calculate EQBSL
    links.forEach(link => {
        const eqbsl = link.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 };
        link.expectation = eqbsl.b + (eqbsl.a * eqbsl.u);
        link.controversy = eqbsl.b * eqbsl.d;
        link.uncertainty = eqbsl.u;
    });

    return { nodes: Array.from(nodesMap.values()), links };
}

// === PROVENANCE GRAPH ===
// Shows source → event_type → target relationships
function buildProvenanceGraph(data) {
    const nodesMap = new Map();
    const links = [];

    // Infer event types from evidence content
    const eventTypes = new Map();

    data.evidence?.slice(0, 400).forEach(e => {
        const eventType = e.content?.type || e.content?.tool || 'observation';

        // Create event type node if new
        if (!eventTypes.has(eventType)) {
            eventTypes.set(eventType, {
                id: `type_${eventType}`,
                label: eventType.toUpperCase(),
                type: 'eventType',
                count: 0,
                eqbsl: { b: 0.7, d: 0.1, u: 0.2, a: 0.5 }
            });
        }
        eventTypes.get(eventType).count++;

        // Create target node from evidence content
        let targetId = null;
        let targetLabel = null;

        if (e.content?.path) {
            // Extract first path segment as target
            const parts = e.content.path.split('/').filter(p => p);
            if (parts.length > 0) {
                targetId = `target_${parts[0]}`;
                targetLabel = `/${parts[0]}`;
            }
        } else if (e.content?.tool === 'subfinder') {
            targetId = 'target_subdomains';
            targetLabel = 'Subdomains';
        } else if (e.content?.tool === 'nmap') {
            targetId = 'target_ports';
            targetLabel = 'Open Ports';
        } else if (e.content?.tool === 'whatweb') {
            targetId = 'target_tech';
            targetLabel = 'Tech Stack';
        }

        if (targetId && !nodesMap.has(targetId)) {
            nodesMap.set(targetId, {
                id: targetId,
                label: targetLabel,
                type: 'target',
                eqbsl: { b: 0.6, d: 0.15, u: 0.25, a: 0.5 }
            });
        }

        // Link event type to target
        if (targetId) {
            const linkKey = `type_${eventType}->${targetId}`;
            if (!links.find(l => `${l.source}->${l.target}` === linkKey)) {
                links.push({
                    source: `type_${eventType}`,
                    target: targetId,
                    type: 'observes',
                    eqbsl: { b: 0.65, d: 0.1, u: 0.25, a: 0.5 }
                });
            }
        }
    });

    // Add event type nodes
    eventTypes.forEach(node => nodesMap.set(node.id, node));

    // Create source (agent) nodes and link to event types
    const agents = new Set();
    data.evidence?.forEach(e => agents.add(e.sourceAgent));

    agents.forEach(agent => {
        nodesMap.set(`source_${agent}`, {
            id: `source_${agent}`,
            label: agent,
            type: 'source',
            eqbsl: { b: 0.85, d: 0.03, u: 0.12, a: 0.5 }
        });
    });

    // Link sources to event types they produce (only if both nodes exist)
    data.evidence?.forEach(e => {
        const eventType = e.content?.type || e.content?.tool || 'observation';
        const sourceId = `source_${e.sourceAgent}`;
        const targetId = `type_${eventType}`;

        // Only add link if both nodes exist
        if (nodesMap.has(sourceId) && nodesMap.has(targetId)) {
            const linkKey = `${sourceId}->${targetId}`;
            if (!links.find(l => `${l.source}->${l.target}` === linkKey)) {
                links.push({
                    source: sourceId,
                    target: targetId,
                    type: 'emits',
                    eqbsl: { b: 0.8, d: 0.05, u: 0.15, a: 0.5 }
                });
            }
        }
    });

    // Calculate EQBSL
    links.forEach(link => {
        const eqbsl = link.eqbsl || { b: 0.5, d: 0.2, u: 0.3, a: 0.5 };
        link.expectation = eqbsl.b + (eqbsl.a * eqbsl.u);
        link.controversy = eqbsl.b * eqbsl.d;
        link.uncertainty = eqbsl.u;
    });

    return { nodes: Array.from(nodesMap.values()), links };
}

function generateGraphHtml(nodes, links, data) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shannon EQBSL Knowledge Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%); 
            color: #fff; 
            overflow: hidden; 
        }
        
        /* Header */
        #header { 
            position: fixed; top: 0; left: 0; right: 0; 
            padding: 16px 24px; 
            background: rgba(15, 15, 26, 0.8); 
            backdrop-filter: blur(20px); 
            z-index: 100; 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        #header h1 { font-size: 1.4rem; font-weight: 600; }
        #header h1 span { color: #4ecdc4; }
        
        #stats { display: flex; gap: 16px; }
        .stat { 
            padding: 8px 16px; 
            background: rgba(255,255,255,0.05); 
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px; 
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .stat-value { font-size: 1.2rem; font-weight: 700; color: #4ecdc4; }
        .stat-label { font-size: 0.8rem; color: rgba(255,255,255,0.6); }
        
        /* Graph */
        #graph { width: 100vw; height: 100vh; }
        
        /* Tooltip */
        #tooltip { 
            position: absolute; 
            background: rgba(15, 15, 26, 0.98); 
            padding: 16px; 
            border-radius: 12px; 
            font-size: 0.85rem; 
            pointer-events: none; 
            opacity: 0; 
            transition: opacity 0.2s; 
            max-width: 380px; 
            border: 1px solid rgba(78, 205, 196, 0.3);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        .tooltip-title { font-weight: 600; font-size: 0.9rem; margin-bottom: 8px; color: #4ecdc4; }
        .tooltip-row { display: flex; justify-content: space-between; padding: 4px 0; }
        .tooltip-label { color: rgba(255,255,255,0.6); }
        .tooltip-value { font-weight: 500; }
        
        /* EQBSL Tensor Bar */
        .tensor-bar { 
            display: flex; 
            height: 12px; 
            border-radius: 6px; 
            overflow: hidden; 
            margin: 8px 0; 
            background: rgba(255,255,255,0.1);
        }
        .tensor-b { background: linear-gradient(90deg, #4ecdc4, #2d9c95); }
        .tensor-d { background: linear-gradient(90deg, #ff6b6b, #c0392b); }
        .tensor-u { background: linear-gradient(90deg, #ffd93d, #f1c40f); }
        
        .tensor-labels { display: flex; justify-content: space-between; font-size: 0.7rem; color: rgba(255,255,255,0.5); }
        
        /* EQBSL Info Panel */
        #eqbsl-panel {
            position: fixed;
            top: 80px;
            right: 20px;
            width: 280px;
            background: rgba(15, 15, 26, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 16px;
            z-index: 50;
        }
        #eqbsl-panel h3 { 
            font-size: 0.9rem; 
            font-weight: 600; 
            margin-bottom: 12px; 
            color: #4ecdc4;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .eqbsl-formula { 
            font-family: 'Courier New', monospace; 
            font-size: 0.8rem;
            background: rgba(78, 205, 196, 0.1);
            padding: 8px 12px;
            border-radius: 6px;
            margin: 8px 0;
        }
        .eqbsl-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 0;
            font-size: 0.8rem;
        }
        .eqbsl-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        
        /* Legend */
        #legend { 
            position: fixed; 
            bottom: 20px; 
            right: 20px; 
            background: rgba(15, 15, 26, 0.9); 
            backdrop-filter: blur(20px);
            padding: 16px; 
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .legend-title { font-weight: 600; font-size: 0.8rem; margin-bottom: 8px; color: rgba(255,255,255,0.6); }
        .legend-item { display: flex; align-items: center; gap: 10px; margin: 6px 0; font-size: 0.8rem; }
        .legend-dot { width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.3); }
        .legend-line { width: 28px; height: 4px; border-radius: 2px; }
        .legend-divider { height: 1px; background: rgba(255,255,255,0.1); margin: 10px 0; }
        
        /* Controls */
        #controls { 
            position: fixed; 
            bottom: 20px; 
            left: 20px; 
            display: flex; 
            flex-direction: column;
            gap: 8px; 
            max-width: 200px; 
        }
        button { 
            padding: 10px 16px; 
            background: rgba(255,255,255,0.05); 
            border: 1px solid rgba(255,255,255,0.15); 
            color: #fff; 
            border-radius: 8px; 
            cursor: pointer; 
            transition: all 0.2s;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            font-weight: 500;
        }
        button:hover { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.3); }
        button.active { background: rgba(78, 205, 196, 0.2); border-color: #4ecdc4; color: #4ecdc4; }
        
        .controls-group { font-size: 0.7rem; color: rgba(255,255,255,0.4); margin-bottom: 4px; }
    </style>
</head>
<body>
    <div id="header">
        <h1>🔮 Shannon <span>EQBSL</span> Knowledge Graph</h1>
        <div id="stats">
            <div class="stat">
                <span class="stat-value">${nodes.length}</span>
                <span class="stat-label">Nodes</span>
            </div>
            <div class="stat">
                <span class="stat-value">${links.length}</span>
                <span class="stat-label">Edges</span>
            </div>
            <div class="stat">
                <span class="stat-value">${data.evidence?.length || 0}</span>
                <span class="stat-label">Evidence</span>
            </div>
            <div class="stat">
                <span class="stat-value">${data.claims?.length || 0}</span>
                <span class="stat-label">Claims</span>
            </div>
        </div>
    </div>
    
    <svg id="graph"></svg>
    <div id="tooltip"></div>
    
    <div id="eqbsl-panel">
        <h3>📐 EQBSL Tensor</h3>
        <div class="eqbsl-item">
            <div class="eqbsl-dot" style="background:#4ecdc4"></div>
            <strong>b</strong> = Belief (confidence true)
        </div>
        <div class="eqbsl-item">
            <div class="eqbsl-dot" style="background:#ff6b6b"></div>
            <strong>d</strong> = Disbelief (confidence false)
        </div>
        <div class="eqbsl-item">
            <div class="eqbsl-dot" style="background:#ffd93d"></div>
            <strong>u</strong> = Uncertainty (lack of evidence)
        </div>
        <div class="eqbsl-item">
            <div class="eqbsl-dot" style="background:#9b59b6"></div>
            <strong>a</strong> = Base rate (prior)
        </div>
        <div class="eqbsl-formula">E = b + a·u</div>
        <div style="font-size:0.75rem; color:rgba(255,255,255,0.5);">
            Expectation combines belief with prior-weighted uncertainty
        </div>
    </div>
    
    
    <div id="legend">
        <div class="legend-title">NODE TYPES</div>
        <!-- Dynamic Node Types will be inserted here -->
        <div id="legend-nodes"></div>
        <div class="legend-divider"></div>
        <div class="legend-title">EDGE MEANING</div>
        <div class="legend-item"><div class="legend-line" style="background:#4ecdc4"></div> High Expectation</div>
        <div class="legend-item"><div class="legend-line" style="background:#ffd93d"></div> Uncertain</div>
        <div class="legend-item"><div class="legend-line" style="background:#ff6b6b"></div> Low Expectation</div>
    </div>
    
    <div id="controls">
        <div class="controls-group">VIEW</div>
        <button onclick="resetZoom()">⟲ Reset Zoom</button>
        <button onclick="toggleForce()" id="forceBtn">⏸ Pause Simulation</button>
        <div class="controls-group" style="margin-top:12px">EDGE STYLE</div>
        <button id="edgeModeBtn" class="active" onclick="cycleEdgeMode()">Expectation</button>
    </div>
    
    <script>
        const nodes = ${JSON.stringify(nodes)};
        const links = ${JSON.stringify(links)};
        
        // Node type definitions
        const nodeDefinitions = {
            'tool': { color: '#4ecdc4', label: 'Tool / Evidence' },
            'evidence': { color: '#4ecdc4', label: 'Tool / Evidence' },
            'agent': { color: '#9b59b6', label: 'Agent / Source' },
            'source': { color: '#9b59b6', label: 'Agent / Source' },
            'domain': { color: '#3498db', label: 'Domain / Target' },
            'target': { color: '#3498db', label: 'Domain / Target' },
            'claim': { color: '#e74c3c', label: 'Claim / Finding' },
            'eventType': { color: '#f39c12', label: 'Event Type' },
            'type': { color: '#f39c12', label: 'Event Type' },
            'port': { color: '#1abc9c', label: 'Port / Service' }
        };

        // Populate Legend dynamically
        const presentTypes = new Set(nodes.map(n => n.type));
        const legendContainer = document.getElementById('legend-nodes');
        const addedLabels = new Set();

        Object.keys(nodeDefinitions).forEach(type => {
            if (presentTypes.has(type)) {
                const def = nodeDefinitions[type];
                if (!addedLabels.has(def.label)) {
                    addedLabels.add(def.label);
                    const div = document.createElement('div');
                    div.className = 'legend-item';
                    div.innerHTML = \`<div class="legend-dot" style="background:\${def.color}"></div> \${def.label}\`;
                    legendContainer.appendChild(div);
                }
            }
        });
        
        // Node type to color mapping (derived from definitions)
        const nodeColors = {};
        Object.keys(nodeDefinitions).forEach(k => nodeColors[k] = nodeDefinitions[k].color);
        nodeColors.default = '#95a5a6';
        
        const width = window.innerWidth, height = window.innerHeight;
        const svg = d3.select('#graph').attr('width', width).attr('height', height);
        const g = svg.append('g');
        
        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on('zoom', (e) => g.attr('transform', e.transform));
        svg.call(zoom);
        
        // Edge color scale
        const edgeColorScale = d3.scaleLinear()
            .domain([0, 0.5, 1])
            .range(['#ff6b6b', '#ffd93d', '#4ecdc4']);
        
        // Force simulation
        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-200))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(30));
        
        // Create edges with EQBSL-based styling
        const link = g.append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(links)
            .join('line')
            .attr('stroke', d => edgeColorScale(d.expectation || 0.5))
            .attr('stroke-opacity', d => 0.3 + (1 - (d.uncertainty || 0.5)) * 0.6)
            .attr('stroke-width', d => 1.5 + (d.expectation || 0.5) * 3);
        
        // Create nodes with type-based coloring
        const node = g.append('g')
            .attr('class', 'nodes')
            .selectAll('circle')
            .data(nodes)
            .join('circle')
            .attr('r', d => {
                if (d.type === 'agent' || d.type === 'source') return 18;
                if (d.type === 'claim') return 12;
                if (d.type === 'tool') return 14;
                return 10;
            })
            .attr('fill', d => nodeColors[d.type] || nodeColors.default)
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('filter', 'drop-shadow(0 2px 4px rgba(0,0,0,0.3))')
            .call(drag(simulation));
        
        // Node labels (for larger nodes)
        const labels = g.append('g')
            .attr('class', 'labels')
            .selectAll('text')
            .data(nodes.filter(n => n.type === 'agent' || n.type === 'source' || n.type === 'tool'))
            .join('text')
            .text(d => d.label.substring(0, 12))
            .attr('font-size', '9px')
            .attr('fill', '#fff')
            .attr('text-anchor', 'middle')
            .attr('dy', 3)
            .style('pointer-events', 'none')
            .style('text-shadow', '0 1px 2px rgba(0,0,0,0.8)');
        
        const tooltip = d3.select('#tooltip');
        
        // Format tensor bar HTML
        function tensorBarHtml(eqbsl) {
            const b = (eqbsl.b * 100).toFixed(1);
            const d = (eqbsl.d * 100).toFixed(1);
            const u = (eqbsl.u * 100).toFixed(1);
            return \`
                <div class="tensor-bar">
                    <div class="tensor-b" style="width:\${b}%"></div>
                    <div class="tensor-d" style="width:\${d}%"></div>
                    <div class="tensor-u" style="width:\${u}%"></div>
                </div>
                <div class="tensor-labels">
                    <span>b: \${b}%</span>
                    <span>d: \${d}%</span>
                    <span>u: \${u}%</span>
                </div>
            \`;
        }
        
        // Node tooltip
        node.on('mouseover', (e, d) => {
            const eqbsl = d.eqbsl || {b:0.33, d:0.33, u:0.34, a:0.5};
            const expectation = ((eqbsl.b + eqbsl.a * eqbsl.u) * 100).toFixed(1);
            
            tooltip.style('opacity', 1)
                .html(\`
                    <div class="tooltip-title">\${d.type.toUpperCase()}</div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Label</span>
                        <span class="tooltip-value">\${d.label}</span>
                    </div>
                    \${d.agent ? '<div class="tooltip-row"><span class="tooltip-label">Agent</span><span class="tooltip-value">' + d.agent + '</span></div>' : ''}
                    <div class="tooltip-row">
                        <span class="tooltip-label">Expectation</span>
                        <span class="tooltip-value" style="color:#4ecdc4">\${expectation}%</span>
                    </div>
                    <div style="margin-top:10px; font-size:0.75rem; color:rgba(255,255,255,0.6)">EQBSL Tensor</div>
                    \${tensorBarHtml(eqbsl)}
                \`)
                .style('left', (e.pageX + 15) + 'px')
                .style('top', (e.pageY - 10) + 'px');
        }).on('mouseout', () => tooltip.style('opacity', 0));
        
        // Edge tooltip
        link.on('mouseover', (e, d) => {
            const eqbsl = d.eqbsl || {b:0.5, d:0.2, u:0.3, a:0.5};
            tooltip.style('opacity', 1)
                .html(\`
                    <div class="tooltip-title">RELATION: \${d.type}</div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Expectation</span>
                        <span class="tooltip-value" style="color:#4ecdc4">\${((d.expectation || 0.5) * 100).toFixed(1)}%</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Uncertainty</span>
                        <span class="tooltip-value" style="color:#ffd93d">\${((d.uncertainty || 0.5) * 100).toFixed(1)}%</span>
                    </div>
                    <div style="margin-top:10px; font-size:0.75rem; color:rgba(255,255,255,0.6)">EQBSL Tensor</div>
                    \${tensorBarHtml(eqbsl)}
                \`)
                .style('left', (e.pageX + 15) + 'px')
                .style('top', (e.pageY - 10) + 'px');
        }).on('mouseout', () => tooltip.style('opacity', 0));
        
        // Simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node
                .attr('cx', d => d.x)
                .attr('cy', d => d.y);
            
            labels
                .attr('x', d => d.x)
                .attr('y', d => d.y);
        });
        
        // Drag behavior
        function drag(simulation) {
            return d3.drag()
                .on('start', (e, d) => {
                    if (!e.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x; d.fy = d.y;
                })
                .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
                .on('end', (e, d) => {
                    if (!e.active) simulation.alphaTarget(0);
                    d.fx = null; d.fy = null;
                });
        }
        
        // Controls
        let isRunning = true;
        function toggleForce() {
            isRunning = !isRunning;
            document.getElementById('forceBtn').textContent = isRunning ? '⏸ Pause Simulation' : '▶ Resume Simulation';
            if (isRunning) simulation.restart();
            else simulation.stop();
        }
        
        function resetZoom() {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }
        
        // Edge mode cycling
        const edgeModes = ['Expectation', 'Uncertainty', 'Controversy'];
        let edgeModeIdx = 0;
        
        function cycleEdgeMode() {
            edgeModeIdx = (edgeModeIdx + 1) % edgeModes.length;
            const mode = edgeModes[edgeModeIdx];
            const btn = document.getElementById('edgeModeBtn');
            btn.textContent = mode;
            
            link.transition().duration(400)
                .attr('stroke', d => {
                    if (mode === 'Expectation') return edgeColorScale(d.expectation || 0.5);
                    if (mode === 'Uncertainty') return d3.interpolateYlOrRd(d.uncertainty || 0.5);
                    if (mode === 'Controversy') return d3.interpolatePurples(0.3 + (d.controversy || 0) * 5);
                    return '#555';
                })
                .attr('stroke-width', d => {
                    if (mode === 'Expectation') return 1.5 + (d.expectation || 0.5) * 3;
                    if (mode === 'Uncertainty') return 1.5 + (d.uncertainty || 0.5) * 4;
                    if (mode === 'Controversy') return 1.5 + (d.controversy || 0) * 12;
                    return 2;
                });
        }
        
        // Initial zoom to fit
        setTimeout(() => {
            const bounds = g.node().getBBox();
            const dx = bounds.width, dy = bounds.height;
            const x = bounds.x + dx / 2, y = bounds.y + dy / 2;
            const scale = 0.8 / Math.max(dx / width, dy / height);
            const translate = [width / 2 - scale * x, height / 2 - scale * y];
            svg.transition().duration(1000)
                .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
        }, 2000);
    </script>
</body>
</html>`;
}
