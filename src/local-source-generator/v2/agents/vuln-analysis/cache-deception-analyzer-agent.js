/**
 * CacheDeceptionAnalyzerAgent - Vary analysis and path-suffix deception
 *
 * Tries dynamic endpoints with static-looking suffixes (e.g., /index.php/fake.css)
 * and examines content-type/cache headers; inspects Vary header for risks.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class CacheDeceptionAnalyzerAgent extends BaseAgent {
  constructor(options = {}) {
    super('CacheDeceptionAnalyzerAgent', options);

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
      evidence_events: ['cache_deception_risk'],
      model_updates: [],
      claims: ['cache_deception_possible'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 80,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    this.staticSuffixes = ['.css', '.js', '.png', '.jpg'];
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const candidates = this.pickCandidates(discoveredEndpoints, base);

    const risks = [];
    let tested = 0;

    for (const url of candidates) {
      for (const sfx of this.staticSuffixes) {
        const testUrl = this.appendSuffix(url, sfx);
        ctx.recordNetworkRequest();
        try {
          const res = await fetch(testUrl, { redirect: 'manual' });
          tested++;
          const ct = (res.headers.get('content-type') || '').toLowerCase();
          const vary = res.headers.get('vary') || '';
          const cacheCtl = (res.headers.get('cache-control') || '').toLowerCase();
          const age = res.headers.get('age') || '';
          const isHtml = ct.includes('text/html');
          const looksCached = /public|max-age|s-maxage|immutable/i.test(cacheCtl) || /\d{1,5}/.test(age);

          // Risk when dynamic HTML served on a static-looking path with cacheable headers
          if (isHtml && looksCached) {
            const finding = { baseUrl: url, testUrl, contentType: ct, cacheControl: cacheCtl, vary };
            risks.push(finding);
            ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'cache_deception_risk', target, payload: finding }));
            ctx.emitClaim({ claim_type: 'cache_deception_possible', subject: url, predicate: { suffix: sfx }, base_rate: 0.5 });
            break;
          }

          // Vary analysis: warn if Vary missing important headers when cookies present
          const varyLower = vary.toLowerCase();
          if (!varyLower && res.headers.get('set-cookie')) {
            const finding = { baseUrl: url, testUrl, issue: 'MISSING_VARY_ON_COOKIE' };
            risks.push(finding);
            ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'cache_deception_risk', target, payload: finding }));
            ctx.emitClaim({ claim_type: 'cache_deception_possible', subject: url, predicate: { issue: 'missing_vary_cookie' }, base_rate: 0.4 });
          }
        } catch (_) {
          // ignore
        }
      }
      if (risks.length >= 10) break;
    }

    return { risks, tested };
  }

  appendSuffix(url, suffix) {
    try {
      const u = new URL(url);
      // /path -> /path/suffixpath
      u.pathname = `${u.pathname.replace(/\/$/, '')}/fake${suffix}`;
      return u.toString();
    } catch { return url + `/fake${suffix}`; }
  }

  pickCandidates(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path;
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (/\.php|\.aspx|^\/$|index|home|product|search/i.test(full)) urls.add(full);
    }
    if (urls.size === 0) ['/', '/index.php', '/home'].forEach(p => urls.add(`${base}${p}`));
    return Array.from(urls).slice(0, 20);
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default CacheDeceptionAnalyzerAgent;

