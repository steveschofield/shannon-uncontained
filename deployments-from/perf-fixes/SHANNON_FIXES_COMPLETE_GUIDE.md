# Shannon Fixes - Complete Patch Guide

**Three critical fixes for Shannon's existing issues**

---

## Quick Summary

| Issue | File | Fix Time | Priority |
|:------|:-----|:---------|:---------|
| WAFDetector crash | waf-detector.js | 2 min | 🔴 HIGH |
| Pipeline spam | orchestrator.js | 5 min | 🔴 HIGH |
| BrowserCrawler silent fail | browser-crawler-agent.js | 3 min | 🟡 MEDIUM |

**Total fix time: 10 minutes**

---

## Fix 1: WAFDetector - "ctx is not defined" 🔴

### Find the File

```bash
cd shannon-uncontained

# Find WAFDetector
find . -name "*waf*detector*.js" -o -name "*waf*.js" | grep -v node_modules
```

**Likely locations:**
- `src/local-source-generator/v2/agents/recon/waf-detector.js`
- `src/agents/recon/waf-detector.js`
- `agents/waf-detector.js`

### Apply the Fix

**Option A: Replace entire file**
```bash
# Backup original
cp <path-to-waf-detector.js> <path-to-waf-detector.js>.backup

# Copy fixed version
cp waf-detector-fixed.js <path-to-waf-detector.js>
```

**Option B: Manual fix (if file structure is different)**

1. **Find the bug:**
```bash
grep -n "ctx\." <path-to-waf-detector.js>
```

2. **Look for these patterns:**
```javascript
// WRONG: ctx used in constructor
constructor(options = {}) {
    super('WAFDetector', options);
    ctx.emitEvidence(...);  // ❌ This line is the bug
}

// WRONG: ctx used outside run()
class WAFDetector extends BaseAgent {
    wafData = ctx.getModel(...);  // ❌ Bug
}

// WRONG: method called in constructor that uses ctx
constructor(options = {}) {
    super('WAFDetector', options);
    this.detectWAF();  // ❌ This calls a method that uses ctx
}
```

3. **Fix pattern:**
```javascript
// Move ALL ctx usage to run() method or methods called FROM run()

// CORRECT pattern:
async run(ctx, inputs) {
    // ✅ Use ctx here
    ctx.emitEvidence(...);
    
    // ✅ Or call methods with ctx parameter
    await this.detectWAF(ctx, inputs);
}

async detectWAF(ctx, inputs) {
    // ✅ Accept ctx as parameter
    ctx.emitEvidence(...);
}
```

### Test the Fix

```bash
# Run with just WAFDetector
./shannon.mjs generate http://example.com \
  --agents WAFDetector \
  --output ./test-waf

# Should see:
# ✓ WAFDetector - Completed in X.Xs
# NOT: ✗ WAFDetector - ctx is not defined
```

---

## Fix 2: Pipeline Health Spam 🔴

### Find the File

```bash
cd shannon-uncontained

# Find pipeline health or orchestrator
find . -name "*orchestrator*.js" -o -name "*pipeline*.js" -o -name "*health*.js" | grep -v node_modules
```

**Likely locations:**
- `src/local-source-generator/v2/orchestrator.js`
- `src/local-source-generator/v2/pipeline-health.js`
- `src/orchestrator.js`

### Apply the Fix

**Option A: Replace PipelineHealthMonitor class**

1. **Find the class:**
```bash
grep -n "class.*Pipeline.*Health" <path-to-file.js>
# or
grep -n "decreaseConcurrency" <path-to-file.js>
```

2. **Replace the entire PipelineHealthMonitor class with the one from `pipeline-health-fixed.js`**

**Option B: Manual minimal fix**

If you can't replace the whole class, add these three critical fixes:

**Fix 2A: Add cooldown**
```javascript
class PipelineHealthMonitor {
    constructor() {
        // ... existing code ...
        
        // ✅ ADD THESE:
        this.lastAdjustment = 0;
        this.adjustmentCooldown = 5000; // 5 seconds
        this.warnedAtMinimum = false;
    }
}
```

**Fix 2B: Fix decreaseConcurrency()**
```javascript
decreaseConcurrency() {
    const now = Date.now();
    
    // ✅ ADD: Cooldown check
    if (now - this.lastAdjustment < this.adjustmentCooldown) {
        return; // Don't adjust too frequently
    }
    
    // ✅ ADD: Stop spam at minimum
    if (this.concurrency <= 1) {
        if (!this.warnedAtMinimum) {
            console.warn('⚠️  Pipeline at minimum concurrency');
            this.warnedAtMinimum = true;
        }
        return; // Don't log repeatedly
    }
    
    // Existing decrease logic
    this.concurrency = Math.max(1, this.concurrency - 1);
    this.lastAdjustment = now; // ✅ ADD
    console.log(`📉 Pipeline Health: Decreasing concurrency to ${this.concurrency}`);
}
```

**Fix 2C: Add recovery (optional but recommended)**
```javascript
increaseConcurrency() {
    const now = Date.now();
    
    if (now - this.lastAdjustment < this.adjustmentCooldown) {
        return;
    }
    
    if (this.concurrency >= this.maxConcurrency) {
        return;
    }
    
    this.concurrency = Math.min(this.maxConcurrency, this.concurrency + 1);
    this.lastAdjustment = now;
    console.log(`📈 Pipeline Health: Improving - increasing concurrency to ${this.concurrency}`);
}

// Call this in checkHealth() when error rate is low
checkHealth() {
    // ... existing error check ...
    
    // ✅ ADD: Recovery logic
    const errorRate = this.errors / this.totalRequests;
    if (errorRate < 0.05 && this.concurrency < this.maxConcurrency) {
        this.increaseConcurrency();
    }
}
```

### Test the Fix

```bash
# Run full scan
./shannon.mjs generate http://192.168.1.130:3000 \
  --profile normal \
  --output ./test

# Should see:
# - Few concurrency adjustments (5-10 max)
# - NO spam of 200+ identical messages
# - Recovery when errors stop
```

---

## Fix 3: BrowserCrawlerAgent Silent Failure 🟡

### Find the File

```bash
cd shannon-uncontained

# Find BrowserCrawler
find . -name "*browser*crawler*.js" | grep -v node_modules
```

**Likely locations:**
- `src/local-source-generator/v2/agents/recon/browser-crawler-agent.js`
- `src/agents/recon/browser-crawler.js`

### Apply the Fix

**Option A: Replace entire file**
```bash
# Backup
cp <path-to-browser-crawler.js> <path-to-browser-crawler.js>.backup

# Copy fixed version
cp browser-crawler-fixed.js <path-to-browser-crawler.js>
```

**Option B: Manual minimal fix**

Add dependency checking at the start of run():

```javascript
async run(ctx, inputs) {
    const { target } = inputs;
    
    // ✅ ADD: Check if browser available
    let browserAvailable = false;
    try {
        await import('playwright');
        browserAvailable = true;
    } catch {
        try {
            await import('puppeteer');
            browserAvailable = true;
        } catch {
            browserAvailable = false;
        }
    }
    
    // ✅ ADD: Graceful exit if not available
    if (!browserAvailable) {
        console.warn('⚠️  Browser not available - skipping BrowserCrawlerAgent');
        console.warn('   Install: npm install playwright && npx playwright install chromium');
        return {
            urls: [],
            forms: [],
            javascript_urls: [],
            crawled: false,
        };
    }
    
    // ... rest of existing code ...
}
```

### Install Dependencies (Recommended)

```bash
# Install Playwright (recommended)
npm install playwright
npx playwright install chromium

# Or Puppeteer (alternative)
npm install puppeteer
```

### Test the Fix

```bash
# Test BrowserCrawler
./shannon.mjs generate http://example.com \
  --agents BrowserCrawlerAgent \
  --output ./test-browser

# If dependencies installed:
# ✓ BrowserCrawlerAgent - Completed in 5-10s

# If dependencies missing:
# ⚠️  Browser not available - skipping BrowserCrawlerAgent
# ✓ BrowserCrawlerAgent - Completed in 0.Xs
```

---

## Complete Fix Application Script

```bash
#!/bin/bash

echo "🔧 Applying Shannon fixes..."

# Backup originals
echo "Creating backups..."
find src -name "*waf*detector*.js" -exec cp {} {}.backup \;
find src -name "*orchestrator*.js" -exec cp {} {}.backup \;
find src -name "*browser*crawler*.js" -exec cp {} {}.backup \;

# Apply fixes
echo "Applying fixes..."

# Fix 1: WAFDetector
WAF_FILE=$(find src -name "*waf*detector*.js" | head -1)
if [ -f "$WAF_FILE" ]; then
    echo "Fixing WAFDetector: $WAF_FILE"
    cp waf-detector-fixed.js "$WAF_FILE"
fi

# Fix 2: Pipeline Health
ORCH_FILE=$(find src -name "*orchestrator*.js" | head -1)
if [ -f "$ORCH_FILE" ]; then
    echo "Fixing Pipeline Health: $ORCH_FILE"
    # Manual fix needed - see guide above
    echo "⚠️  Manual fix required - see Fix 2B in guide"
fi

# Fix 3: BrowserCrawler
BROWSER_FILE=$(find src -name "*browser*crawler*.js" | head -1)
if [ -f "$BROWSER_FILE" ]; then
    echo "Fixing BrowserCrawler: $BROWSER_FILE"
    cp browser-crawler-fixed.js "$BROWSER_FILE"
fi

echo "✅ Fixes applied!"
echo ""
echo "Test with:"
echo "./shannon.mjs generate http://192.168.1.130:3000 --output ./test"
```

---

## Verification

After applying all fixes, run:

```bash
# Full test
./shannon.mjs generate http://192.168.1.130:3000 \
  --profile normal \
  --output ./shannon-test-$(date +%s)

# Expected output:
# ✓ WAFDetector - Completed in 2-5s (not "ctx is not defined")
# ⚠️  Browser not available (or ✓ if installed)
# ✓ TechFingerprinterAgent - Completed
# ✓ NetReconAgent - Completed
# 📉 Pipeline Health messages: 5-10 max (not 200+)
# No spam!
```

---

## Rollback

If anything breaks:

```bash
# Restore backups
find src -name "*.backup" -exec bash -c 'mv "$1" "${1%.backup}"' _ {} \;
```

---

## Summary

**What each fix does:**

1. **WAFDetector fix**: Ensures `ctx` is only used inside `run()` method
2. **Pipeline Health fix**: Adds cooldown (5s) and stops spam at minimum concurrency
3. **BrowserCrawler fix**: Checks dependencies, fails gracefully with helpful message

**Priority order:**
1. Fix Pipeline Health first (stops log spam)
2. Fix WAFDetector second (stops error cascade)
3. Fix BrowserCrawler last (optional, can skip)

**Time required:** 10 minutes total

**Risk:** Low - all fixes are backwards compatible and add safety checks

---

## Need Help?

If you encounter issues:

1. Check the backup files (*.backup)
2. Review error messages
3. Compare with the fixed versions provided
4. Rollback if needed

The fixes are designed to be minimal and safe - they only add checks and don't remove functionality.
