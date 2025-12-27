/**
 * SSTIAgent - Server-Side Template Injection detection
 *
 * Sends lightweight framework-agnostic payloads and looks for evaluation artifacts
 * (e.g., 7*7 → 49) to detect templating evaluation.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class SSTIAgent extends BaseAgent {
  constructor(options = {}) {
    super('SSTIAgent', options);

    this.inputs_schema = {
      type: 'object',
      required: ['target'],
      properties: {
        target: { type: 'string' },
        injectionPoints: { type: 'array', description: 'From ParameterDiscoveryAgent', items: { type: 'object' } },
      }
    };

    this.outputs_schema = {
      type: 'object',
      properties: {
        vulnerabilities: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['parameter_discovered','injection_point_identified'], model_nodes: [] };
    this.emits = {
      evidence_events: ['ssti_detected'],
      model_updates: [],
      claims: ['server_side_template_injection'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 120000,
      max_network_requests: 150,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    // Minimal payload set (avoid destructive payloads)
    this.payloads = [
      { payload: '{{7*7}}', expect: '49' },        // Jinja2/Twig
      { payload: '${{7*7}}', expect: '49' },       // Some variants
      { payload: '<%= 7*7 %>', expect: '49' },     // EJS-like
      { payload: '${7*7}', expect: '49' },         // Groovy/EL
    ];
    this.paramHint = ['q','query','name','message','search','title'];
  }

  async run(ctx, inputs) {
    const { target, injectionPoints = [] } = inputs;
    const base = this.normalizeBase(target);

    const vulns = [];
    let tested = 0;

    const points = this.pickPoints(injectionPoints, base);
    const unsafe = !!(ctx.config && ctx.config.unsafeProbes);
    const payloads = unsafe ? [
      ...this.payloads,
      { payload: '{{7*7}}-{{7*7}}', expect: '49-49' },
      { payload: '${{7*7}}${{7*7}}', expect: '49' }
    ] : this.payloads;

    for (const point of points) {
      for (const p of this.payloads) {
        const url = this.inject(point, p.payload);
        ctx.recordNetworkRequest();
        try {
          const res = await fetch(url, { method: 'GET', redirect: 'manual' });
          const text = await res.text();
          tested++;
          if (text && text.includes(p.expect)) {
            const finding = { url: point.baseUrl, param: point.param, marker: p.expect };
            vulns.push(finding);
            ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'ssti_detected', target, payload: finding }));
            ctx.emitClaim({ claim_type: 'server_side_template_injection', subject: point.baseUrl, predicate: { param: point.param }, base_rate: 0.6 });
            break;
          }
        } catch (_) {
          // ignore
        }
      }
    }

    return { vulnerabilities: vulns, tested };
  }

  pickPoints(injectionPoints, base) {
    const points = [];
    for (const ip of injectionPoints) {
      const url = ip?.url || ip?.endpoint || '';
      const param = ip?.param || ip?.name || '';
      if (!url || !param) continue;
      if (!this.paramHint.includes(param) && !/name|msg|title|q|query/i.test(param)) continue;
      const baseUrl = url.startsWith('http') ? url : `${base}${url.startsWith('/') ? '' : '/'}${url}`;
      points.push({ baseUrl, param });
      if (points.length >= 30) break;
    }
    // If none provided, try common endpoints
    if (points.length === 0) {
      for (const path of ['/search','/message','/profile','/view']) {
        for (const param of this.paramHint) {
          points.push({ baseUrl: `${base}${path}`, param });
        }
      }
    }
    return points;
  }

  inject(point, value) {
    const u = new URL(point.baseUrl);
    u.searchParams.set(point.param, value);
    return u.toString();
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default SSTIAgent;
