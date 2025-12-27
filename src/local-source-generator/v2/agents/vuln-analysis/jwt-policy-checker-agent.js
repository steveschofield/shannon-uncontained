/**
 * JWTPolicyCheckerAgent - OAuth/OIDC policy checks
 *
 * Fetches OpenID configuration and flags weak settings (alg=none allowed,
 * missing scopes, insecure response types, none auth methods).
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class JWTPolicyCheckerAgent extends BaseAgent {
  constructor(options = {}) {
    super('JWTPolicyCheckerAgent', options);

    this.inputs_schema = {
      type: 'object',
      required: ['target'],
      properties: {
        target: { type: 'string' }
      }
    };

    this.outputs_schema = {
      type: 'object',
      properties: {
        issues: { type: 'array', items: { type: 'object' } },
        config: { type: 'object' }
      }
    };

    this.requires = { evidence_kinds: [], model_nodes: [] };
    this.emits = {
      evidence_events: ['jwt_policy_issue'],
      model_updates: [],
      claims: ['jwt_policy_weak'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 60000,
      max_network_requests: 4,
      max_tokens: 0,
      max_tool_invocations: 0,
    };
  }

  async run(ctx, inputs) {
    const { target } = inputs;
    const base = this.normalizeBase(target);
    const urls = [
      `${base}/.well-known/openid-configuration`,
      `${base}/.well-known/openid-configuration/`
    ];

    const issues = [];
    let config = null;

    for (const url of urls) {
      ctx.recordNetworkRequest();
      try {
        const res = await fetch(url, { timeout: 10000 });
        if (!res.ok) continue;
        const json = await res.json();
        config = json;
        break;
      } catch (_) { /* try next */ }
    }

    if (config) {
      // id_token algs
      const algs = (config.id_token_signing_alg_values_supported || []).map(x => String(x).toLowerCase());
      if (algs.includes('none')) issues.push({ code: 'ALG_NONE_SUPPORTED', msg: 'Provider allows alg=none for ID tokens' });

      // response types - flag implicit/hybrid if present (not always bad, but riskier)
      const rtypes = (config.response_types_supported || []).map(String);
      if (rtypes.some(t => /token\s*id_token|id_token/i.test(t))) issues.push({ code: 'IMPLICIT_FLOW', msg: 'Implicit/hybrid response types enabled' });

      // token endpoint auth methods
      const authMethods = (config.token_endpoint_auth_methods_supported || []).map(String);
      if (authMethods.includes('none')) issues.push({ code: 'NO_CLIENT_AUTH', msg: 'Token endpoint allows no client auth' });

      // scopes
      const scopes = (config.scopes_supported || []).map(String);
      if (scopes.length && !scopes.includes('openid')) issues.push({ code: 'NO_OPENID_SCOPE', msg: 'scopes_supported missing openid' });

      for (const issue of issues) {
        ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'jwt_policy_issue', target, payload: issue }));
      }
      if (issues.length > 0) {
        ctx.emitClaim({ claim_type: 'jwt_policy_weak', subject: base, predicate: { issues: issues.map(i => i.code) }, base_rate: 0.5 });
      }
    }

    return { issues, config };
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default JWTPolicyCheckerAgent;

