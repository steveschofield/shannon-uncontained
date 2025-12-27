/**
 * IDORProbeAgent - Authorization variance checks
 *
 * Heuristically probes endpoints with numeric/UUID identifiers (path or query)
 * by mutating the identifier and comparing status and body size. If successful
 * responses differ significantly, flags possible IDOR.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class IDORProbeAgent extends BaseAgent {
  constructor(options = {}) {
    super('IDORProbeAgent', options);

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
        findings: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['endpoint_discovered'], model_nodes: [] };
    this.emits = {
      evidence_events: ['idor_possible_detected'],
      model_updates: [],
      claims: ['idor_possible'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 120000,
      max_network_requests: 120,
      max_tokens: 0,
      max_tool_invocations: 0,
    };
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const unsafe = !!(ctx.config && ctx.config.unsafeProbes);
    const cfg = (ctx.config && ctx.config.agentConfig && ctx.config.agentConfig.IDORProbeAgent) || {};
    const maxEndpoints = cfg.maxEndpoints ?? (unsafe ? 50 : 30);
    const maxMutations = cfg.maxMutations ?? 3;
    const candidates = this.findIdEndpoints(discoveredEndpoints, base, maxEndpoints);

    const findings = [];
    let tested = 0;

    const unsafe = !!(ctx.config && ctx.config.unsafeProbes);
    const maxFindings = unsafe ? 20 : 10;
    for (const c of candidates) {
      const baseRes = await this.safeFetch(c.url);
      tested++;
      if (!baseRes.ok) continue;
      const baseText = baseRes.bodyText;
      const baseLen = baseText.length;

      for (const mutated of this.mutate(c, maxMutations)) {
        const res2 = await this.safeFetch(mutated);
        tested++;
        if (res2.ok && Math.abs(res2.bodyText.length - baseLen) > Math.max(200, baseLen * 0.3)) {
          const finding = { baseUrl: c.url, mutated, delta: res2.bodyText.length - baseLen };
          findings.push(finding);
          ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'idor_possible_detected', target, payload: finding }));
          ctx.emitClaim({ claim_type: 'idor_possible', subject: c.url, predicate: { mutated }, base_rate: 0.5 });
          break;
        }
        if (findings.length >= maxFindings) break;
      }
      if (findings.length >= maxFindings) break;
    }

    return { findings, tested };
  }

  async safeFetch(url) {
    try {
      const res = await fetch(url, { redirect: 'manual' });
      const text = await res.text();
      return { ok: res.status >= 200 && res.status < 300, bodyText: text, status: res.status };
    } catch { return { ok: false, bodyText: '', status: 0 }; }
  }

  findIdEndpoints(discovered, base, maxEndpoints) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path || '';
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (/(?:^|\/)\d+(?:$|\/|\?|#)/.test(full) || /[?&](?:id|user|uid|account|order|item)=/i.test(full)) {
        urls.add(full);
      }
    }
    return Array.from(urls).slice(0, maxEndpoints).map(url => ({ url }));
  }

  mutate(c, maxMutations = 3) {
    const muts = [];
    try {
      const u = new URL(c.url);
      // Query param ids
      for (const [k, v] of u.searchParams.entries()) {
        if (/^(id|user|uid|account|order|item)$/i.test(k) && /^(\d+|[a-f0-9-]{8,})$/i.test(v)) {
          if (/^\d+$/.test(v)) {
            muts.push(this.set(u, k, String(parseInt(v, 10) + 1)));
          } else {
            muts.push(this.set(u, k, v.replace(/[0-9a-f]/i, m => (m === 'f' ? '0' : 'f'))));
          }
        }
      }
      // Path param ids
      const parts = u.pathname.split('/');
      const idx = parts.findIndex(p => /^\d+$/.test(p));
      if (idx > -1) {
        const p2 = [...parts];
        p2[idx] = String(parseInt(parts[idx], 10) + 1);
        const u2 = new URL(u.toString());
        u2.pathname = p2.join('/');
        muts.push(u2.toString());
      }
    } catch { /* ignore */ }
    return muts.slice(0, maxMutations);
  }

  set(u, k, v) { const u2 = new URL(u.toString()); u2.searchParams.set(k, v); return u2.toString(); }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default IDORProbeAgent;
