# Rate Limiting Integration Guide

**How to add rate limiting to Shannon agents**

---

## Quick Start

### 1. Initialize Rate Limiter

**In your orchestrator or main entry point:**

```javascript
import { GlobalRateLimiter } from './utils/global-rate-limiter.js';
import { loadProfile } from './config/rate-limit-config.js';

// Initialize with profile
const profile = loadProfile('normal'); // or 'conservative', 'aggressive'
const limiter = GlobalRateLimiter.getInstance(profile.global);

// Or auto-detect from target
import { getRecommendedProfile } from './config/rate-limit-config.js';
const profileName = getRecommendedProfile('https://juice-shop.herokuapp.com');
const profile = loadProfile(profileName);
const limiter = GlobalRateLimiter.getInstance(profile.global);
```

---

## Agent Integration Patterns

### Pattern 1: Simple Fetch Wrapper (Recommended)

**Use for:** Most agents that make HTTP requests

```javascript
import { withRateLimit } from './utils/global-rate-limiter.js';

export class YourAgent extends BaseAgent {
    constructor(options = {}) {
        super('YourAgent', options);
        
        // Initialize rate limiter for this agent
        this.rateLimit = withRateLimit('YourAgent');
    }

    async run(ctx, inputs) {
        // Example: Make rate-limited request
        try {
            const response = await this.rateLimit.fetch(
                'https://target.com/api/endpoint',
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ test: 'data' }),
                },
                3 // retries
            );

            // Request automatically rate-limited, retried on error
            const data = await response.json();
            
        } catch (error) {
            // Error already recorded in rate limiter
            console.error('Request failed:', error);
        }
    }
}
```

---

### Pattern 2: Manual Throttling

**Use for:** Agents that need fine-grained control

```javascript
import { GlobalRateLimiter } from './utils/global-rate-limiter.js';

export class YourAgent extends BaseAgent {
    constructor(options = {}) {
        super('YourAgent', options);
        this.limiter = GlobalRateLimiter.getInstance();
    }

    async run(ctx, inputs) {
        for (const endpoint of endpoints) {
            try {
                // Wait for rate limiter
                await this.limiter.throttle('YourAgent');

                // Make request
                const response = await fetch(endpoint, { timeout: 10000 });

                // Record success
                this.limiter.recordSuccess('YourAgent');

            } catch (error) {
                // Record error
                this.limiter.recordError('YourAgent', 'timeout');
            }
        }
    }
}
```

---

## Agent-Specific Integrations

### ParameterDiscoveryAgent

**File:** `parameter-discovery-agent.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class ParameterDiscoveryAgent extends BaseAgent {
    constructor(options = {}) {
        super('ParameterDiscoveryAgent', options);
        
        // Add rate limiting
        this.rateLimit = withRateLimit('ParameterDiscoveryAgent');
        
        // Load agent-specific config
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.ParameterDiscoveryAgent || {};
        
        this.maxEndpoints = agentConfig.maxEndpoints || 10;
        this.maxParameters = agentConfig.maxParameters || 20;
        this.requestDelay = agentConfig.requestDelay || 100;
    }

    async probeHiddenParameters(ctx, endpoints, baseUrl, target) {
        const hidden = [];
        
        // CHANGED: Limit endpoints tested
        const testEndpoints = endpoints.slice(0, this.maxEndpoints);

        for (const endpoint of testEndpoints) {
            const url = endpoint.url || endpoint;
            
            try {
                const parsed = new URL(url);
                const basePath = `${parsed.origin}${parsed.pathname}`;

                // CHANGED: Limit parameters tested
                for (const paramName of this.commonParams.slice(0, this.maxParameters)) {
                    ctx.recordNetworkRequest();
                    
                    try {
                        // CHANGED: Use rate-limited fetch
                        const testUrl = `${basePath}?${paramName}=test`;
                        const response = await this.rateLimit.fetch(testUrl, {
                            method: 'GET',
                            headers: {
                                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
                            },
                            timeout: 10000,
                        });
                        
                        // ... rest of logic
```

---

### NoSQLInjectionAgent

**File:** `nosql-injection-agent.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class NoSQLInjectionAgent extends BaseAgent {
    constructor(options = {}) {
        super('NoSQLInjectionAgent', options);
        
        this.rateLimit = withRateLimit('NoSQLInjectionAgent');
        
        // Load config
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.NoSQLInjectionAgent || {};
        
        this.maxInjectionPoints = agentConfig.maxInjectionPoints || 15;
        this.maxPayloads = agentConfig.maxPayloads || 7;
        this.requestDelay = agentConfig.requestDelay || 100;
        
        // CHANGED: Reduce payloads based on config
        this.mongoOperators = this.mongoOperators.slice(0, this.maxPayloads);
    }

    async testInjectionPoints(ctx, injectionPoints, target) {
        const vulnerabilities = [];
        
        // CHANGED: Limit injection points
        const nosqlPoints = injectionPoints
            .filter(/* ... */)
            .slice(0, this.maxInjectionPoints);

        for (const point of nosqlPoints) {
            // CHANGED: Use rate-limited fetch
            const response = await this.rateLimit.fetch(testUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            
            // ... rest of logic
```

---

### EnhancedNucleiScanAgent

**File:** `enhanced-nuclei-scan-agent.js`

**Changes needed:**

```javascript
import { GlobalRateLimiter } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class EnhancedNucleiScanAgent extends BaseAgent {
    constructor(options = {}) {
        super('EnhancedNucleiScanAgent', options);
        
        this.limiter = GlobalRateLimiter.getInstance();
        
        // Load config
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.EnhancedNucleiScanAgent || {};
        
        this.nucleiArgs = agentConfig.nucleiArgs || '-rate-limit 50 -bulk-size 10 -c 10';
        this.maxTemplates = agentConfig.maxTemplates || 3000;
    }

    async runNucleiScan(ctx, target, depth, customTemplates) {
        // ... existing code ...

        // CHANGED: Use config-based rate limiting
        const command = [
            'nuclei',
            `-u ${target}`,
            templateArgs,
            customTemplates,
            '-jsonl',
            `-o ${tempFile}`,
            '-silent',
            '-stats',
            this.nucleiArgs,  // CHANGED: Use configured args
            '-timeout 20',
            '-retries 1',
        ].join(' ');

        // ... rest of code
```

---

### BusinessLogicFuzzer

**File:** `business-logic-fuzzer.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class BusinessLogicFuzzer extends BaseAgent {
    constructor(options = {}) {
        super('BusinessLogicFuzzer', options);
        
        this.rateLimit = withRateLimit('BusinessLogicFuzzer');
        
        // Load config
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.BusinessLogicFuzzer || {};
        
        const maxDiscountTests = agentConfig.maxDiscountTests || 7;
        const maxPriceTests = agentConfig.maxPriceTests || 6;
        this.requestDelay = agentConfig.requestDelay || 150;
        
        // CHANGED: Reduce test cases based on config
        this.discountTests = this.discountTests.slice(0, maxDiscountTests);
        this.priceTests = this.priceTests.slice(0, maxPriceTests);
    }

    async testDiscountAbuse(ctx, endpoints, target) {
        // ... existing code ...
        
        for (const test of this.discountTests) {
            try {
                // CHANGED: Use rate-limited fetch
                const response = await this.rateLimit.fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: test.code }),
                });
                
                // ... rest of logic
```

---

### CSRFDetector

**File:** `csrf-detector.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class CSRFDetector extends BaseAgent {
    constructor(options = {}) {
        super('CSRFDetector', options);
        
        this.rateLimit = withRateLimit('CSRFDetector');
        
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.CSRFDetector || {};
        
        this.maxEndpoints = agentConfig.maxEndpoints || 20;
    }

    async testMissingCSRFTokens(ctx, endpoints, target) {
        // CHANGED: Limit endpoints
        const stateChangingEndpoints = endpoints
            .filter(/* ... */)
            .slice(0, this.maxEndpoints);

        for (const endpoint of stateChangingEndpoints) {
            // CHANGED: Use rate-limited fetch
            const response = await this.rateLimit.fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: method !== 'DELETE' ? JSON.stringify({ test: 'data' }) : undefined,
            });
            
            // ... rest of logic
```

---

### SSRFDetector

**File:** `ssrf-detector.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class SSRFDetector extends BaseAgent {
    constructor(options = {}) {
        super('SSRFDetector', options);
        
        this.rateLimit = withRateLimit('SSRFDetector');
        
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.SSRFDetector || {};
        
        this.maxParameters = agentConfig.maxParameters || 10;
        this.requestDelay = agentConfig.requestDelay || 150;
    }

    async testCloudMetadata(ctx, parameters, target) {
        // CHANGED: Limit parameters
        for (const param of parameters.slice(0, this.maxParameters)) {
            // ... existing code ...
            
            // CHANGED: Use rate-limited fetch
            const response = await this.rateLimit.fetch(testUrl, {
                method: 'GET',
            });
            
            // ... rest of logic
```

---

### GraphQLTester

**File:** `graphql-tester.js`

**Changes needed:**

```javascript
import { withRateLimit } from '../utils/global-rate-limiter.js';
import { loadProfile } from '../config/rate-limit-config.js';

export class GraphQLTester extends BaseAgent {
    constructor(options = {}) {
        super('GraphQLTester', options);
        
        this.rateLimit = withRateLimit('GraphQLTester');
        
        const profile = loadProfile(options.profile || 'normal');
        const agentConfig = profile.agents.GraphQLTester || {};
        
        this.maxDepthTest = agentConfig.maxDepthTest || 30;
        this.maxBatchSize = agentConfig.maxBatchSize || 50;
    }

    async testDepthLimits(ctx, endpoint, target) {
        // CHANGED: Use configured depth
        const deepQuery = this.createDeepQuery(this.maxDepthTest);
        
        // CHANGED: Use rate-limited fetch
        const response = await this.rateLimit.fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: deepQuery }),
        });
        
        // ... rest of logic
    }

    async testBatchingAttacks(ctx, endpoint, target) {
        // CHANGED: Use configured batch size
        const batch = [];
        for (let i = 0; i < this.maxBatchSize; i++) {
            batch.push({ query: '{ __typename }' });
        }
        
        // CHANGED: Use rate-limited fetch
        const response = await this.rateLimit.fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(batch),
        });
        
        // ... rest of logic
```

---

## Configuration Files

### Create shannon.config.js

```javascript
import { RATE_LIMIT_PROFILES } from './config/rate-limit-config.js';

export default {
    // Default profile
    rateLimit: {
        profile: 'normal',
        
        // Or custom config
        global: {
            requestsPerSecond: 10,
            burstSize: 20,
            minDelay: 100,
        },
        
        // Per-agent overrides
        agents: {
            EnhancedNucleiScanAgent: {
                nucleiArgs: '-rate-limit 50 -bulk-size 10 -c 10',
            },
        },
    },
};
```

---

## Command-Line Usage

```bash
# Use profile
./shannon.mjs generate https://target.com \
  --profile conservative

# Or specify in config file
./shannon.mjs generate https://target.com \
  --config ./configs/juice-shop-conservative.yaml
```

---

## Monitoring Rate Limits

```javascript
import { GlobalRateLimiter } from './utils/global-rate-limiter.js';

// Get status during scan
const limiter = GlobalRateLimiter.getInstance();
const status = limiter.getStatus();

console.log(status);
/*
{
  requestsPerSecond: 10,
  currentDelay: 100,
  tokens: 15.3,
  totalRequests: 247,
  successfulRequests: 235,
  errorCount: 12,
  consecutiveErrors: 0,
  errorRate: '4.86%',
  circuitOpen: false,
  isThrottling: false
}
*/

// Get per-agent stats
const agentStats = limiter.getAgentStats();
console.log(agentStats);
/*
{
  ParameterDiscoveryAgent: {
    requests: 89,
    errors: 3,
    lastRequest: 1703567890123
  },
  NoSQLInjectionAgent: {
    requests: 52,
    errors: 0,
    lastRequest: 1703567890456
  }
}
*/
```

---

## Testing Rate Limits

```bash
# Test conservative profile on Juice Shop
./shannon.mjs generate http://localhost:3000 \
  --profile conservative \
  --agents ParameterDiscoveryAgent,NoSQLInjectionAgent

# Monitor for crashes
docker stats juice-shop-container

# If it crashes → use 'stealth' profile
# If it survives → can use 'normal' profile
```

---

## Summary

### Steps to Integrate:

1. **Copy files:**
   - `global-rate-limiter.js` → `src/utils/`
   - `rate-limit-config.js` → `src/config/`

2. **Update each agent:**
   - Import `withRateLimit`
   - Initialize in constructor
   - Replace `fetch()` with `this.rateLimit.fetch()`
   - Apply config limits (maxEndpoints, maxPayloads, etc.)

3. **Test:**
   - Start with 'conservative' profile
   - Monitor target health
   - Adjust profile as needed

4. **Deploy:**
   - Use 'normal' for most targets
   - Use 'conservative' for fragile targets
   - Use 'aggressive' for resilient targets

---

**Estimated integration time:** 2-3 hours for all agents

**Impact:** Prevents target crashes, improves reliability, enables production use
