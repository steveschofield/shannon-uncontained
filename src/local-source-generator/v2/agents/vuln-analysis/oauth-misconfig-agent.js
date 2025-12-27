/**
 * OAuthMisconfigAgent - Redirect URI tampering and scope checks
 *
 * Attempts safe GET to authorization endpoints with crafted redirect_uri to
 * see if external hosts are accepted; inspects errors for hints and checks
 * if scope escalation patterns are reflected/accepted.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

export class OAuthMisconfigAgent extends BaseAgent {
  constructor(options = {}) {
    super('OAuthMisconfigAgent', options);

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
        issues: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['endpoint_discovered'], model_nodes: [] };
    this.emits = {
      evidence_events: ['oauth_misconfig'],
      model_updates: [],
      claims: ['oauth_misconfiguration'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 60,
      max_tokens: 0,
      max_tool_invocations: 0,
    };
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const candidates = this.pickAuthEndpoints(discoveredEndpoints, base);
    const issues = [];
    let tested = 0;

    const isLab = !!(ctx.config && ctx.config.unsafeProbes && Array.isArray(ctx.config.labAgents) && ctx.config.labAgents.includes(this.name));
    const labRedirect = process.env.OAUTH_LAB_REDIRECT_URL || 'https://example.org/lab-callback';
    for (const url of candidates) {
      // Attempt redirect_uri tampering with external host
      const tampered = this.withParams(url, {
        client_id: 'test-client',
        redirect_uri: isLab ? labRedirect : 'https://example.org/callback',
        response_type: 'code',
        scope: 'openid profile admin'
      });
      ctx.recordNetworkRequest();
      try {
        const res = await fetch(tampered, { redirect: 'manual' });
        tested++;
        const location = res.headers.get('location') || '';
        const text = await this.safeText(res);
        // If server directly redirects to example.org or includes it in Location, misconfig
        if (/example\.org/i.test(location) || (isLab && new URL(labRedirect).host && location.includes(new URL(labRedirect).host))) {
          issues.push({ url, issue: 'REDIRECT_URI_ACCEPTED', location });
          this.emit(ctx, target, { code: 'REDIRECT_URI_ACCEPTED', url, location });
          if (isLab) {
            try { await this.writeLabPoC(inputs, tampered, url); } catch {}
          }
        }
        // If error contains allowed redirect URIs or weak validation hints
        if (/redirect_uri/i.test(text) && /allowed|invalid|mismatch/i.test(text)) {
          issues.push({ url, issue: 'REDIRECT_URI_HINT', snippet: text.slice(0, 120) });
          this.emit(ctx, target, { code: 'REDIRECT_URI_HINT', url });
        }
        // If elevated scope reflected/accepted in error message
        if (/admin|\bread\b|\bwrite\b/.test(text)) {
          issues.push({ url, issue: 'SCOPE_ESCALATION_HINT', snippet: text.slice(0, 120) });
          this.emit(ctx, target, { code: 'SCOPE_ESCALATION_HINT', url });
        }
      } catch (_) { /* ignore */ }
      if (issues.length >= 10) break;
    }

    return { issues, tested };
  }

  emit(ctx, target, payload) {
    ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'oauth_misconfig', target, payload }));
    ctx.emitClaim({ claim_type: 'oauth_misconfiguration', subject: target, predicate: { code: payload.code }, base_rate: 0.4 });
  }

  withParams(url, params) {
    try { const u = new URL(url); Object.entries(params).forEach(([k,v])=>u.searchParams.set(k,String(v))); return u.toString(); } catch { return url; }
  }

  async safeText(res) { try { return await res.text(); } catch { return ''; } }

  pickAuthEndpoints(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path || '';
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      if (/oauth|authorize|auth|login|connect\/authorize/i.test(full)) urls.add(full);
    }
    if (urls.size === 0) ['/oauth/authorize','/connect/authorize','/auth','/login'].forEach(p => urls.add(`${base}${p}`));
    return Array.from(urls).slice(0, 20);
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }

  async writeLabPoC(inputs, authUrl, endpoint) {
    const outDir = inputs.outputDir || inputs.workspace || null;
    if (!outDir) return;
    const u = new URL(endpoint);
    const labDir = path.join(outDir, 'deliverables', 'lab', 'oauth');
    await fsp.mkdir(labDir, { recursive: true });
    const file = path.join(labDir, `${u.host.replace(/[:/\\]/g,'_')}.txt`);
    const content = `# OAuth Code Flow Lab PoC (do not use on production)\n\nAuthorize URL (open in browser):\n${authUrl}\n\nNote: Set OAUTH_LAB_REDIRECT_URL to a controlled endpoint to capture the code in a lab environment.`;
    await fsp.writeFile(file, content, 'utf-8');
  }
}

export default OAuthMisconfigAgent;
