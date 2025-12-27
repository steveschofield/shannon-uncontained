/**
 * OpenRedirectAgent - Open redirect detection
 *
 * Probes candidate endpoints/parameters and checks if the server
 * issues a 3xx redirect to an arbitrary external domain.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';

export class OpenRedirectAgent extends BaseAgent {
  constructor(options = {}) {
    super('OpenRedirectAgent', options);

    this.inputs_schema = {
      type: 'object',
      required: ['target'],
      properties: {
        target: { type: 'string', description: 'Base target URL' },
        discoveredEndpoints: {
          type: 'array',
          description: 'Previously discovered endpoints from recon/crawl',
          items: { type: 'object' }
        },
      }
    };

    this.outputs_schema = {
      type: 'object',
      properties: {
        findings: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED], model_nodes: [] };
    this.emits = {
      evidence_events: ['open_redirect_detected'],
      model_updates: [],
      claims: ['open_redirect'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 80,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    this.paramNames = [
      'next','return','returnUrl','return_url','redirect','redirectTo','redirect_uri','url','dest','target','continue','goto','to'
    ];
    this.testHost = 'http://example.org';
  }

  buildTests(baseUrl) {
    const tests = [];
    for (const p of this.paramNames) {
      tests.push({ query: `${p}=${encodeURIComponent(this.testHost)}` });
      tests.push({ query: `${p}=//example.org` });
      tests.push({ query: `${p}=${encodeURIComponent(`//example.org`)}` });
    }
    // Common endpoint paths
    const paths = ['/login','/signin','/logout','/redirect','/callback','/oauth/callback','/auth/callback','/continue'];
    return { tests, paths };
  }

  async tryUrl(url) {
    try {
      const res = await fetch(url, { redirect: 'manual' });
      const isRedirect = res.status >= 300 && res.status < 400;
      const loc = res.headers.get('location') || '';
      return { status: res.status, location: loc, isRedirect };
    } catch (e) {
      return { error: e.message };
    }
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const { tests, paths } = this.buildTests(base);

    const candidates = new Set();
    // From discovered endpoints
    for (const ep of discoveredEndpoints) {
      const path = ep?.path || ep?.url || '';
      if (!path) continue;
      const lower = path.toLowerCase();
      if (this.paramNames.some(n => lower.includes(`${n}=`)) || paths.some(p => lower.includes(p))) {
        candidates.add(path.startsWith('http') ? path : `${base}${path.startsWith('/') ? '' : '/'}${path}`);
      }
    }
    // Add generic candidates
    for (const p of paths) candidates.add(`${base}${p}`);

    const results = [];
    let tested = 0;

    for (const c of candidates) {
      for (const t of tests) {
        const sep = c.includes('?') ? '&' : '?';
        const url = `${c}${sep}${t.query}`;
        ctx.recordNetworkRequest();
        const r = await this.tryUrl(url);
        tested++;
        if (r.isRedirect && r.location && /example\.org/i.test(r.location)) {
          const finding = { url: c, param: t.query.split('=')[0], redirected_to: r.location, status: r.status };
          results.push(finding);

          ctx.emitEvidence(createEvidenceEvent({
            source: this.name,
            event_type: 'open_redirect_detected',
            target,
            payload: finding,
          }));

          ctx.emitClaim({
            claim_type: 'open_redirect',
            subject: c,
            predicate: { param: finding.param },
            base_rate: 0.6,
          });
          // One finding per candidate is enough
          break;
        }
      }
    }

    return { findings: results, tested };
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default OpenRedirectAgent;

