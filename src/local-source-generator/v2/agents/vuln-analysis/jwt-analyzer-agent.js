/**
 * JWTAnalyzerAgent - Lightweight JWT analysis (no brute force)
 *
 * Detects JWTs in Authorization headers and Set-Cookie responses, decodes
 * header/payload, and flags weak algs or missing/odd claims.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent } from '../../worldmodel/evidence-graph.js';

export class JWTAnalyzerAgent extends BaseAgent {
  constructor(options = {}) {
    super('JWTAnalyzerAgent', options);

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
        tokens_found: { type: 'array', items: { type: 'object' } },
        issues: { type: 'array', items: { type: 'object' } },
        tested: { type: 'number' }
      }
    };

    this.requires = { evidence_kinds: ['http_response','endpoint_discovered'], model_nodes: [] };
    this.emits = {
      evidence_events: ['jwt_detected','jwt_misconfig'],
      model_updates: [],
      claims: ['jwt_misconfiguration','jwt_alg_none','jwt_missing_claims'],
      artifacts: []
    };

    this.default_budget = {
      max_time_ms: 90000,
      max_network_requests: 40,
      max_tokens: 0,
      max_tool_invocations: 0,
    };

    this.cookieNames = ['jwt','token','id_token','access_token','auth','session'];
  }

  async run(ctx, inputs) {
    const { target, discoveredEndpoints = [] } = inputs;
    const base = this.normalizeBase(target);
    const endpoints = this.pickEndpoints(discoveredEndpoints, base);

    const tokens = [];
    const issues = [];
    let tested = 0;

    for (const url of endpoints) {
      ctx.recordNetworkRequest();
      try {
        const res = await fetch(url, { method: 'GET', redirect: 'manual' });
        tested++;
        // Authorization rarely appears in responses; focus on Set-Cookie
        const setCookie = this.getSetCookie(res.headers);
        for (const c of setCookie) {
          const found = this.extractJWTFromCookie(c);
          if (found) {
            const decoded = this.decodeJWT(found.token);
            tokens.push({ url, cookie: found.name, header: decoded.header, payload: decoded.payload });
            ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'jwt_detected', target, payload: { url, cookie: found.name } }));
            // Analyze
            const tokenIssues = this.analyze(decoded.header, decoded.payload);
            for (const issue of tokenIssues) {
              issues.push({ url, cookie: found.name, ...issue });
              ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'jwt_misconfig', target, payload: issue }));
              const ct = issue.code === 'ALG_NONE' ? 'jwt_alg_none' : 'jwt_misconfiguration';
              ctx.emitClaim({ claim_type: ct, subject: url, predicate: { cookie: found.name, code: issue.code }, base_rate: 0.6 });
            }

            // Lab-only: generate PoC alg=none token artifact when unsafe + lab selected
            const isLab = !!(ctx.config && ctx.config.unsafeProbes && Array.isArray(ctx.config.labAgents) && ctx.config.labAgents.includes(this.name));
            if (isLab && tokenIssues.some(i => i.code === 'ALG_NONE')) {
              const poc = this.generateNoneToken({ sub: 'lab', iat: Math.floor(Date.now()/1000) });
              ctx.emitEvidence(createEvidenceEvent({ source: this.name, event_type: 'jwt_poc_generated', target, payload: { url, cookie: found.name, token: poc } }));
            }
          }
        }
      } catch (_) {
        // ignore
      }
      if (tokens.length >= 10) break;
    }

    return { tokens_found: tokens, issues, tested };
  }

  pickEndpoints(discovered, base) {
    const urls = new Set();
    for (const ep of discovered) {
      const u = ep?.url || ep?.path;
      if (!u) continue;
      const full = u.startsWith('http') ? u : `${base}${u.startsWith('/') ? '' : '/'}${u}`;
      // Focus on auth/profile/me endpoints for cookies
      if (/login|auth|profile|me|account|session|user/i.test(full)) urls.add(full);
    }
    if (urls.size === 0) {
      ['/','/login','/profile','/me','/account'].forEach(p => urls.add(`${base}${p}`));
    }
    return Array.from(urls).slice(0, 20);
  }

  getSetCookie(headers) {
    const values = [];
    // Node fetch flattens; iterate
    headers.forEach((v, k) => {
      if (k.toLowerCase() === 'set-cookie') values.push(v);
    });
    return values;
  }

  extractJWTFromCookie(cookieStr) {
    // Look for known cookie names and three-part JWT pattern
    const nameMatch = this.cookieNames.map(n => new RegExp(`(^|;\\s*)${n}=([^;]+)`, 'i'));
    for (const r of nameMatch) {
      const m = cookieStr.match(r);
      if (m) {
        const value = decodeURIComponent(m[2]);
        if (value.split('.').length === 3) {
          return { name: m[0].split('=')[0].trim().replace(/^;\s*/, ''), token: value };
        }
      }
    }
    // Generic search
    const jwt = cookieStr.match(/[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/);
    if (jwt) return { name: 'unknown', token: jwt[0] };
    return null;
  }

  b64urlDecode(s) {
    try {
      const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
      const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
      return JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
    } catch { return null; }
  }

  decodeJWT(token) {
    const parts = token.split('.');
    const header = this.b64urlDecode(parts[0]);
    const payload = this.b64urlDecode(parts[1]);
    return { header, payload };
  }

  analyze(header = {}, payload = {}) {
    const issues = [];
    const alg = String(header.alg || '').toLowerCase();
    if (!alg) issues.push({ code: 'ALG_MISSING', msg: 'JWT alg missing' });
    if (alg === 'none') issues.push({ code: 'ALG_NONE', msg: 'JWT uses alg=none' });
    // Header kid present could imply file traversal tricks if unsafely used
    if ('kid' in header && (typeof header.kid !== 'string' || header.kid.length === 0)) {
      issues.push({ code: 'KID_SUSPICIOUS', msg: 'JWT header kid suspicious/empty' });
    }
    // Claims sanity
    const required = ['iss','sub','aud','exp','iat'];
    const missing = required.filter(k => !(k in payload));
    if (missing.length > 0) issues.push({ code: 'MISSING_CLAIMS', msg: `Missing claims: ${missing.join(', ')}` });
    if (payload.exp && typeof payload.exp === 'number') {
      const now = Math.floor(Date.now()/1000);
      if (payload.exp - now > 31536000) issues.push({ code: 'LONG_EXP', msg: 'Token expiry > 1 year' });
    }
    return issues;
  }

  generateNoneToken(payload) {
    const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
    const h = enc({ alg: 'none', typ: 'JWT' });
    const p = enc(payload);
    return `${h}.${p}.`;
  }

  normalizeBase(target) {
    try { const u = new URL(target); return `${u.protocol}//${u.host}`; } catch { return target.replace(/\/$/, ''); }
  }
}

export default JWTAnalyzerAgent;
