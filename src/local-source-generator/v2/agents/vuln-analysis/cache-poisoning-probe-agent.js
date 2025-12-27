/**
 * CachePoisoningProbeAgent - Safe header probes for cache poisoning risk
 *
 * Sends requests with benign headers (X-Forwarded-Host/Proto, etc.) and checks
 * for reflection in Location/body or cache headers that indicate risk.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class CachePoisoningProbeAgent extends BaseAgent {
  constructor(options = {}) {
    super('CachePoisoningProbeAgent', options);

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
      evidence_events: ['cache_poisoning_risk'],
      model_updates: [],
      claims: ['cache_poisoning_possible'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 60,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    this.headersToTest = (host) => ({
      'X-Forwarded-Host': host,
      'X-Original-Host': host,
      'X-Forwarded-Proto': 'http',
      'X-Forwarded-Port': '80',
      'Forwarded': `host=${host};proto=http`,
      'Via': '1.1 example-proxy',
    });
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const candidates = this.pickCandidates(discoveredEndpoints, base);
    const risks = [];
    let tested = 0;

    const unsafe = !!(ctx.config && ctx.config.unsafeProbes);
    const maxFindings = unsafe ? 20 : 10;

    for (const url of candidates) {
      const poisonHost = 'poison.example.org';
      const headers = this.headersToTest(poisonHost);
      ctx.recordNetworkRequest();
      try {
        const res = await fetch(url, { headers, redirect: 'manual' });
        tested++;
        const text = await this.safeText(res);
        const location = res.headers.get('location') || '';
        const cacheHeader = res.headers.get('x-cache') || res.headers.get('cf-cache-status') || res.headers.get('age') || '';

        const reflected = location.includes(poisonHost) || (text && text.includes(poisonHost));
        const riskyCache = /HIT|MISS|EXPIRED|STALE|\d{1,5}/i.test(cacheHeader);

        if (reflected || riskyCache) {
          const finding = { url, reflected, location, cacheHeader };
          risks.push(finding);
          ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'cache_poisoning_risk', target, payload: finding }));
          ctx.emitClaim({ claim_type: 'cache_poisoning_possible', subject: url, predicate: { reflected, cache: cacheHeader }, base_rate: 0.5 });
        }
      } catch (_) {
        // ignore
      }
      if (risks.length >= maxFindings) break;
    }

    return { risks, tested };
  }

  async safeText(res) {
    try { return await res.text(); } catch { return ''; }
  }

  pickCandidates(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path;
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (/^\/$|index|home|login|product|search/i.test(full)) urls.add(full);
    }
    if (urls.size === 0) ['/', '/index', '/home', '/search'].forEach(p => urls.add(`${base}${p}`));
    return Array.from(urls).slice(0, 20);
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default CachePoisoningProbeAgent;
