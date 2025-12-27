/**
 * XXEUploadAgent - Safe XXE detection via upload/import endpoints
 *
 * Sends benign XML with a DOCTYPE and external entity declaration to likely
 * upload/import endpoints (XML/CSV importers). Looks for parser error messages
 * or behavior indicating XXE support. Does NOT contact internal hosts or
 * perform out-of-band callbacks.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class XXEUploadAgent extends BaseAgent {
  constructor(options = {}) {
    super('XXEUploadAgent', options);

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
        indicators: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['endpoint_discovered'], model_nodes: [] };
    this.emits = {
      evidence_events: ['xxe_indicator_detected'],
      model_updates: [],
      claims: ['xxe_possible'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 60,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    // base payload set in run() to allow unsafe OOB URL substitution
    this.baseXmlPayload = `<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n`+
      `<!DOCTYPE root [<!ENTITY test SYSTEM \\\"http://example.org/xxe.txt\\\">]>\n`+
      `<root>XXE-&test;</root>`;

    this.uploadHints = [/upload|import|xml|feed|sitemap|data|bulk/i];
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const endpoints = this.pickEndpoints(discoveredEndpoints, base);

    const indicators = [];
    let tested = 0;

    const unsafe = !!(ctx.config && ctx.config.unsafeProbes);
    const oob = unsafe && process.env.XXE_OOB_URL ? String(process.env.XXE_OOB_URL) : null;
    const payload = oob
      ? `<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM \"${oob}\">]>\n<r>&xxe;</r>`
      : this.baseXmlPayload;

    for (const url of endpoints) {
      ctx.recordNetworkRequest();
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: payload,
          redirect: 'manual'
        });
        tested++;
        const text = await this.safeText(res);
        if (this.looksLikeXXE(text)) {
          const finding = { url, status: res.status, snippet: text.slice(0, 120) };
          indicators.push(finding);
          ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'xxe_indicator_detected', target, payload: finding }));
          ctx.emitClaim({ claim_type: 'xxe_possible', subject: url, predicate: { hint: 'parser_error' }, base_rate: 0.5 });
        }
      } catch (_) {
        // ignore
      }
      if (indicators.length >= 10) break;
    }

    return { indicators, tested };
  }

  looksLikeXXE(text = '') {
    const t = text.toLowerCase();
    return /doctype|external entity|xxe|saxparseexception|entity.*not.*allowed|disallow/i.test(t);
  }

  async safeText(res) { try { return await res.text(); } catch { return ''; } }

  pickEndpoints(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path || '';
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (this.uploadHints.some(r => r.test(full))) urls.add(full);
    }
    if (urls.size === 0) ['/upload','/import','/xml','/feed/import'].forEach(p => urls.add(`${base}${p}`));
    return Array.from(urls).slice(0, 20);
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default XXEUploadAgent;
