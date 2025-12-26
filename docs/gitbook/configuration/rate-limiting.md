# Rate Limiting

Shannon includes a global, adaptive rate limiter to avoid overwhelming targets and triggering WAFs. It supports per‑agent limits, token‑bucket bursting, backoff on errors, and simple wrappers for HTTP usage.

## Quick Start

Initialize the limiter from your entrypoint (CLI, script, or orchestrator setup) and choose a profile.

```javascript
// Entry file at repo root (ESM)
import { GlobalRateLimiter } from '../../src/utils/global-rate-limiter.js';
import { loadProfile, getRecommendedProfile } from '../../src/config/rate-limit-config.js';

const target = 'https://example.com';
const profileName = getRecommendedProfile(target); // 'stealth' | 'conservative' | 'normal' | 'aggressive'
const profile = loadProfile(profileName);

// Create singleton with global profile settings
const limiter = GlobalRateLimiter.getInstance(profile.global);
console.log('Rate limiter initialized with profile:', profileName);
```

Profiles live in `src/config/rate-limit-config.js` and include per‑agent knobs (e.g., payload limits, per‑agent delays) you can consult inside agents.

## Agent Integration Patterns

### 1) Simple fetch wrapper (recommended)

Wrap `fetch` with rate limiting and retries.

```javascript
// From inside an agent (ESM path relative to repo root shown)
import { withRateLimit } from '../../../utils/global-rate-limiter.js';

export class YourAgent {
  constructor() {
    this.rateLimit = withRateLimit('YourAgent');
  }

  async run(ctx) {
    try {
      const res = await this.rateLimit.fetch('https://example.com/api', { method: 'GET' }, 3);
      const data = await res.json();
      // ...
    } catch (err) {
      // Errors already accounted for by limiter (backoff, counters)
      ctx.setStatus(`Request failed: ${err.message}`);
    }
  }
}
```

### 2) Manual throttling (fine‑grained control)

```javascript
import { GlobalRateLimiter } from '../../../utils/global-rate-limiter.js';

export class YourAgent {
  constructor() {
    this.limiter = GlobalRateLimiter.getInstance();
  }

  async run() {
    await this.limiter.throttle('YourAgent');
    const res = await fetch('https://example.com/slow-op', { timeout: 10000 });
    this.limiter.recordSuccess('YourAgent');
  }
}
```

## Profiles and Target Heuristics

- Profiles: `stealth`, `conservative`, `normal`, `aggressive`
- Helper `getRecommendedProfile(target)` picks a safer default for local/dev targets and a faster one for CDN/cloud targets.
- Configure per‑agent caps (e.g., `maxEndpoints`, `requestDelay`) under `agents` in the profile and consult those inside agents to scale workload.

```javascript
import { loadProfile } from '../../src/config/rate-limit-config.js';

const profile = loadProfile('conservative');
const nosqlLimits = profile.agents?.NoSQLInjectionAgent;
if (nosqlLimits) {
  // e.g., limit tests based on profile
}
```

## Tips

- Use `stealth` for prod bug bounties or strict WAFs.
- Use `conservative` for local/dev containers (e.g., Juice Shop).
- Start slower and only increase to `normal`/`aggressive` when you confirm the target can handle it.
- The limiter opens a circuit breaker after repeated errors; it auto‑resets after a cooldown.
