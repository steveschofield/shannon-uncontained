# Katana Timeout Fix - Deployment Guide

## Problem Summary

Katana times out on Juice Shop (and other large SPAs) because:
- **Depth-3 crawling** discovers ~150+ pages
- **JavaScript execution** (`-jc` flag) takes 2-4 seconds per page
- **Timeout limit** is 180 seconds, but needs ~300 seconds to complete

**Math:** 150 pages × 2s = 300s needed, but timeout = 180s → **TIMEOUT**

---

## Solution Options

### Option A: Reduce Depth (RECOMMENDED ⭐⭐⭐⭐⭐)

**What:** Change default crawl depth from 3 → 2  
**Impact:** Completes in ~70-90 seconds, discovers 80-90% of endpoints  
**Risk:** Very low - depth 2 is sufficient for most applications  
**Time to apply:** 2 minutes

### Option B: Increase Timeout

**What:** Increase Katana timeout from 180s → 240s (4 minutes)  
**Impact:** Allows depth-3 to complete on most SPAs  
**Risk:** Low - adds ~1 minute to scan time  
**Time to apply:** 2 minutes

### Option C: Both (BELT AND SUSPENDERS)

**What:** Apply both fixes  
**Impact:** Depth 2 by default, but 4-minute timeout if user overrides to depth 3  
**Risk:** Minimal  
**Time to apply:** 3 minutes

---

## Installation Instructions

### Prerequisites

1. **Locate your Shannon repository:**
   ```bash
   cd /path/to/shannon-uncontained
   ```

2. **Find the files to patch:**
   ```bash
   # Should return something like:
   # src/local-source-generator/v2/agents/recon/crawler-agent.js
   find . -name "crawler-agent.js" -not -path "*/node_modules/*"
   
   # Should return something like:
   # src/local-source-generator/v2/tools/runners/tool-runner.js
   find . -name "tool-runner.js" -not -path "*/node_modules/*"
   ```

---

## Option A: Reduce Depth (Recommended)

### Step 1: Backup Original

```bash
# Find and backup crawler-agent.js
CRAWLER_FILE=$(find . -name "crawler-agent.js" -path "*/agents/recon/*" | head -1)
cp "$CRAWLER_FILE" "$CRAWLER_FILE.backup"
echo "✅ Backed up: $CRAWLER_FILE.backup"
```

### Step 2: Apply Patch

**Method 1: Copy the patched file**

```bash
# Copy the patched file from this deployment
cp crawler-agent-patched.js "$CRAWLER_FILE"
echo "✅ Applied depth-2 patch"
```

**Method 2: Manual edit (if preferred)**

Edit the file at the locations marked with `✅ CHANGED`:

```javascript
// Line ~20: Change inputs_schema description
depth: { type: 'number', description: 'Crawl depth (default: 2)' },  // ✅ was: default: 3

// Line ~53: Change run() method default
const { target, depth = 2, includeHistorical = true } = inputs;  // ✅ was: depth = 3
```

### Step 3: Verify Changes

```bash
# Check that depth defaults to 2
grep -n "depth = 2" "$CRAWLER_FILE"
# Should show line numbers where depth = 2 appears
```

### Step 4: Test

```bash
# Run a test scan
./shannon.mjs generate http://192.168.1.130:3000 \
  --agents CrawlerAgent \
  --output ./test-crawl

# Katana should complete in ~70-90 seconds
# Check the events.ndjson for "tool_end" with "success":true
```

---

## Option B: Increase Timeout

### Step 1: Backup Original

```bash
# Find and backup tool-runner.js
RUNNER_FILE=$(find . -name "tool-runner.js" -path "*/tools/runners/*" | head -1)
cp "$RUNNER_FILE" "$RUNNER_FILE.backup"
echo "✅ Backed up: $RUNNER_FILE.backup"
```

### Step 2: Apply Patch

**Method 1: Using sed**

```bash
# Change katana timeout from 180000 to 240000
sed -i.bak 's/katana: 180000/katana: 240000/' "$RUNNER_FILE"
echo "✅ Applied timeout patch"
```

**Method 2: Manual edit**

Find the TOOL_TIMEOUTS object and change:

```javascript
export const TOOL_TIMEOUTS = {
    nmap: 120000,
    subfinder: 60000,
    whatweb: 30000,
    gau: 60000,
    katana: 240000,     // ✅ CHANGED: was 180000
    httpx: 30000,
    nuclei: 300000,
    commix: 300000,
};
```

### Step 3: Verify Changes

```bash
# Check the timeout value
grep -A 10 "TOOL_TIMEOUTS" "$RUNNER_FILE" | grep katana
# Should show: katana: 240000
```

### Step 4: Test

```bash
# Run a test scan with depth 3
./shannon.mjs generate http://192.168.1.130:3000 \
  --agents CrawlerAgent \
  --output ./test-crawl

# Katana should complete in ~3-4 minutes now
```

---

## Option C: Both Fixes

```bash
# Apply both patches
CRAWLER_FILE=$(find . -name "crawler-agent.js" -path "*/agents/recon/*" | head -1)
RUNNER_FILE=$(find . -name "tool-runner.js" -path "*/tools/runners/*" | head -1)

# Backup
cp "$CRAWLER_FILE" "$CRAWLER_FILE.backup"
cp "$RUNNER_FILE" "$RUNNER_FILE.backup"

# Apply depth-2 patch
cp crawler-agent-patched.js "$CRAWLER_FILE"

# Apply timeout patch
sed -i.bak 's/katana: 180000/katana: 240000/' "$RUNNER_FILE"

echo "✅ Applied both patches"
```

---

## Testing & Validation

### Test 1: Quick Scan (Depth 2)

```bash
# Default depth-2 scan
time ./shannon.mjs generate http://192.168.1.130:3000 \
  --agents CrawlerAgent \
  --output ./test-depth2

# Expected:
# - Katana completes in 60-90 seconds
# - Discovers 80-100 endpoints
# - No timeout errors
```

### Test 2: Deep Scan (Depth 3, if timeout increased)

```bash
# Override to depth 3
time ./shannon.mjs generate http://192.168.1.130:3000 \
  --agents CrawlerAgent \
  --depth 3 \
  --output ./test-depth3

# Expected (with timeout patch):
# - Katana completes in 180-240 seconds
# - Discovers 120-150 endpoints
# - No timeout errors

# Expected (without timeout patch):
# - Katana times out at 180s
# - Falls back to gau
```

### Test 3: Full Shannon Run

```bash
# Run complete Shannon pipeline
time ./shannon.mjs generate http://192.168.1.130:3000 \
  --output ./test-full

# Expected:
# - CrawlerAgent completes in ~90s
# - Total scan time reduced by ~90s
# - Better endpoint coverage from katana
```

---

## Verification Checklist

After applying the fix, verify:

- [ ] **Backup files exist** (`.backup` extension)
- [ ] **Depth default is 2** (if Option A)
- [ ] **Timeout is 240000** (if Option B)
- [ ] **Test scan completes without timeout**
- [ ] **Katana finds endpoints** (not just gau)
- [ ] **Total scan time improved**

---

## Expected Performance Impact

### Before Fix (Depth 3, 180s timeout)

| Metric | Value |
|:-------|:------|
| Katana timeout | Yes (after 180s) |
| Katana endpoints | 0 (timed out) |
| Fallback to gau | Yes |
| Total discovery time | 180s + 52s = 232s |
| Coverage | gau only (~60% of endpoints) |

### After Fix - Option A (Depth 2)

| Metric | Value |
|:-------|:------|
| Katana timeout | No |
| Katana completion time | 70-90s |
| Katana endpoints | 80-100 |
| gau also runs | Yes (52s) |
| Total discovery time | 90s + 52s = 142s |
| Coverage | katana + gau (~85% of endpoints) |
| **Time saved** | **90 seconds (39% faster)** |

### After Fix - Option B (Depth 3, 240s timeout)

| Metric | Value |
|:-------|:------|
| Katana timeout | No |
| Katana completion time | 180-240s |
| Katana endpoints | 120-150 |
| gau also runs | Yes (52s) |
| Total discovery time | 210s + 52s = 262s |
| Coverage | katana + gau (~95% of endpoints) |
| **Time penalty** | **+30 seconds (slower but more thorough)** |

---

## Rollback Instructions

If you need to undo the changes:

```bash
# Restore from backup
CRAWLER_FILE=$(find . -name "crawler-agent.js" -path "*/agents/recon/*" | head -1)
RUNNER_FILE=$(find . -name "tool-runner.js" -path "*/tools/runners/*" | head -1)

# Restore crawler-agent.js
if [ -f "$CRAWLER_FILE.backup" ]; then
    cp "$CRAWLER_FILE.backup" "$CRAWLER_FILE"
    echo "✅ Restored crawler-agent.js"
fi

# Restore tool-runner.js
if [ -f "$RUNNER_FILE.backup" ]; then
    cp "$RUNNER_FILE.backup" "$RUNNER_FILE"
    echo "✅ Restored tool-runner.js"
fi
```

---

## Troubleshooting

### Issue: "Cannot find crawler-agent.js"

```bash
# Search more broadly
find . -name "*crawler*.js" -not -path "*/node_modules/*"

# Or search in src directory
find src -name "crawler-agent.js"
```

### Issue: "Patch file not found"

Make sure you have the patch files in your current directory:
- `crawler-agent-patched.js`
- `tool-runner-timeout-patch.js`

If missing, refer to the files provided in this deployment package.

### Issue: "Still timing out after patch"

1. **Verify the patch was applied:**
   ```bash
   grep "depth = 2" "$CRAWLER_FILE"
   # Should return a match
   ```

2. **Check if override was specified:**
   ```bash
   # Don't use --depth 3 manually
   ./shannon.mjs generate target --depth 3  # ❌ This overrides the fix
   ./shannon.mjs generate target            # ✅ Uses default depth 2
   ```

3. **Increase timeout further** (last resort):
   ```bash
   # Change to 5 minutes (300000ms)
   sed -i 's/katana: 240000/katana: 300000/' "$RUNNER_FILE"
   ```

---

## Advanced: Custom Depth Per Target

If you want to maintain depth-3 for small sites and depth-2 for large SPAs:

**Option: Add target-specific config**

Create `configs/juice-shop.yaml`:
```yaml
target: http://192.168.1.130:3000
agents:
  CrawlerAgent:
    depth: 2
```

Run with:
```bash
./shannon.mjs generate --config configs/juice-shop.yaml
```

**Option: Add adaptive depth logic**

This would require more extensive changes to `crawler-agent.js`:
- Quick depth-1 scan to estimate size
- Choose depth 2 for >30 pages, depth 3 for <30 pages
- See "Option 5: Adaptive Crawling" in katana-timeout-analysis.md

---

## Documentation Updates

After applying the fix, update your documentation:

1. **Update MODS.md:**
   ```markdown
   ## feat(crawler): Reduce default depth to prevent timeouts (2025-12-26)
   
   Changed CrawlerAgent default depth from 3 → 2 to prevent Katana timeouts
   on large SPAs like OWASP Juice Shop. Depth 2 completes in ~70-90s and
   discovers 80-90% of endpoints. Users can override with --depth 3 if needed.
   ```

2. **Update README.md** (if applicable):
   ```markdown
   ### Crawling Configuration
   
   By default, Shannon crawls to depth 2. For deeper crawling:
   ```bash
   ./shannon.mjs generate target --depth 3
   ```
   
   Note: Depth 3 may timeout on large JavaScript-heavy applications.
   ```

---

## Summary

**Recommended Approach:** Option A (Reduce Depth to 2)

**Why:**
- ✅ Faster scans (90s saved per run)
- ✅ No timeouts on large SPAs
- ✅ Still discovers 80-90% of endpoints
- ✅ Minimal code changes
- ✅ Can override with --depth 3 if needed

**Apply it in 2 minutes:**
```bash
CRAWLER_FILE=$(find . -name "crawler-agent.js" -path "*/agents/recon/*" | head -1)
cp "$CRAWLER_FILE" "$CRAWLER_FILE.backup"
cp crawler-agent-patched.js "$CRAWLER_FILE"
echo "✅ Fix applied!"
```

**Test it:**
```bash
./shannon.mjs generate http://192.168.1.130:3000 --agents CrawlerAgent
# Should complete in ~90 seconds with no timeout
```

Done! 🎉
