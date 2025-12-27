/**
 * RequestSmugglingDetector - Safe CL/TE heuristic probes
 *
 * Does not send malformed requests. Performs header/behavior heuristics to
 * identify stack/proxy combinations where CL/TE issues are likely. Optionally
 * sends benign headers (Expect: 100-continue) and checks behavior.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

export class RequestSmugglingDetector extends BaseAgent {
  constructor(options = {}) {
    super('RequestSmugglingDetector', options);

    this.inputs_schema = {
      type: 'object',
      required: ['target'],
      properties: {
        target: { type: 'string' },
        discoveredEndpoints: { type: 'array', items: { type: 'object' } }
      }
    };

    this.outputs_schema = {
      type: 'object',
      properties: {
        risks: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['endpoint_discovered'], model_nodes: [] };
    this.emits = {
      evidence_events: ['request_smuggling_risk'],
      model_updates: [],
      claims: ['request_smuggling_possible'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 40,
      max_tokens: 0,
      max_tool_invocations: 0,
    };
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const candidates = this.pickCandidates(discoveredEndpoints, base);
    const risks = [];
    let tested = 0;

    const isLab = !!(ctx.config && ctx.config.unsafeProbes && Array.isArray(ctx.config.labAgents) && ctx.config.labAgents.includes(this.name));
    for (const url of candidates) {
      ctx.recordNetworkRequest();
      try {
        // Baseline request
        const res = await fetch(url, { method: 'GET', redirect: 'manual' });
        tested++;
        const server = (res.headers.get('server') || '').toLowerCase();
        const via = (res.headers.get('via') || '').toLowerCase();
        const xCache = (res.headers.get('x-cache') || res.headers.get('cf-cache-status') || '').toLowerCase();
        const connection = (res.headers.get('connection') || '').toLowerCase();
        const te = (res.headers.get('te') || '').toLowerCase();

        // Heuristic indicators: presence of known proxies + origin servers
        const proxyHints = /(akamai|cloudfront|cloudflare|varnish|fastly|proxy|cache|route|ingress)/i;
        const originHints = /(apache|nginx|iis|gunicorn|envoy|haproxy)/i;
        const hasProxy = proxyHints.test(via) || proxyHints.test(server) || xCache.length > 0;
        const hasOrigin = originHints.test(server);
        const keepAlive = connection.includes('keep-alive');
        const teAllowed = te.length > 0; // Rare, but note

        if ((hasProxy && hasOrigin) || teAllowed || keepAlive) {
          const finding = { url, server, via, xCache, connection, teAllowed };
          risks.push(finding);
          ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'request_smuggling_risk', target, payload: finding }));
          ctx.emitClaim({ claim_type: 'request_smuggling_possible', subject: url, predicate: { proxy: via || xCache ? true : false }, base_rate: 0.4 });
        }

        // Lab-only: send extra benign headers that sometimes tickle proxy behavior
        if (isLab) {
          try {
            const labHeaders = {
              'Connection': 'keep-alive, Upgrade',
              'Upgrade': 'h2c',
              'Expect': '100-continue',
              'X-LSG-Lab-Probe': '1'
            };
            const resLab = await fetch(url, { method: 'GET', headers: labHeaders, redirect: 'manual' });
            const labData = {
              url,
              status: resLab.status,
              expects: (resLab.headers.get('expect') || '').toLowerCase(),
              connection: (resLab.headers.get('connection') || '').toLowerCase(),
            };
            // Emit auxiliary info to help lab debugging
            ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'request_smuggling_risk', target, payload: { lab_probe: true, ...labData } }));
          } catch (_) {}

          // Generate raw HTTP PoCs as artifacts for lab use (no sending)
          try {
            await this.writeLabPoCs(inputs, url);
          } catch { /* ignore */ }
        }
      } catch (_) {
        // ignore
      }
      if (risks.length >= 10) break;
    }

    return { risks, tested };
  }

  pickCandidates(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path;
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (/^\/$|^\/api|^\/login|^\/products|^\/search/i.test(full)) urls.add(full);
    }
    if (urls.size === 0) ['/', '/login', '/api', '/search'].forEach(p => urls.add(`${base}${p}`));
    return Array.from(urls).slice(0, 15);
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }

  async writeLabPoCs(inputs, url) {
    const outDir = inputs.outputDir || inputs.workspace || null;
    if (!outDir) return;
    const u = new URL(url);
    const labDir = path.join(outDir, 'deliverables', 'lab', 'request-smuggling');
    await fsp.mkdir(labDir, { recursive: true });
    const file = path.join(labDir, `${u.host.replace(/[:/\\]/g,'_')}.txt`);
    const raw = `# Request Smuggling Lab PoCs (do not use on production)\n\n`+
`# CL.TE (Content-Length with Transfer-Encoding)\n`+
`POST ${u.pathname || '/'} HTTP/1.1\n`+
`Host: ${u.host}\n`+
`Content-Length: 4\n`+
`Transfer-Encoding: chunked\n`+
`\n`+
`0\r\n\r\n`+
`GARB\n\n`+
`# TE.CL (Transfer-Encoding with Content-Length)\n`+
`POST ${u.pathname || '/'} HTTP/1.1\n`+
`Host: ${u.host}\n`+
`Transfer-Encoding: chunked\n`+
`Content-Length: 6\n`+
`\n`+
`5\r\nhello\r\n0\r\n\r\n`+
`\n`+
`# H2C Upgrade probe\n`+
`GET ${u.pathname || '/'} HTTP/1.1\n`+
`Host: ${u.host}\n`+
`Connection: Upgrade, HTTP2-Settings\n`+
`Upgrade: h2c\n`+
`HTTP2-Settings: AAMAAABkAAQAAP__\n\n`;
    await fsp.writeFile(file, raw, 'utf-8');
  }
}

export default RequestSmugglingDetector;
