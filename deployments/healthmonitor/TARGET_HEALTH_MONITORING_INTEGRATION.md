# Target Health Monitoring - Complete Integration Guide

**Problem:** Shannon keeps running even after Juice Shop crashes, wasting time testing a dead target.

**Solution:** Add target health monitoring that detects crashes and stops the scan gracefully.

---

## What This Adds

### Before (Current Behavior)
```
[8:30:00] NetReconAgent running...
[8:30:05] NetReconAgent complete
[8:30:05] CrawlerAgent running...
[8:32:00] <<< JUICE SHOP CRASHES >>>
[8:32:00] CrawlerAgent still running... (against dead target)
[8:35:00] CrawlerAgent timeout
[8:35:00] ParameterDiscoveryAgent running... (against dead target)
[8:40:00] ParameterDiscoveryAgent timeout
... continues for 30 more minutes against dead target
```

### After (With Health Monitoring)
```
[8:30:00] 🏥 Target health monitoring started
[8:30:00] NetReconAgent running...
[8:30:05] NetReconAgent complete
[8:30:05] CrawlerAgent running...
[8:32:00] <<< JUICE SHOP CRASHES >>>
[8:32:05] ⚠️  Target health check failed (1/3)
[8:32:35] ⚠️  Target health check failed (2/3)
[8:33:05] ⚠️  Target health check failed (3/3)
[8:33:05] ❌ TARGET DOWN DETECTED
[8:33:05] 🛑 STOPPING SCAN - Target is unreachable

Scan stopped after 3 minutes (not 30 minutes)
```

---

## Integration Steps

### Step 1: Add Health Monitor File (2 minutes)

```bash
cd shannon-uncontained

# Create utils directory if not exists
mkdir -p src/local-source-generator/v2/utils

# Copy health monitor
cp target-health-monitor.js src/local-source-generator/v2/utils/
```

---

### Step 2: Integrate with Orchestrator (5 minutes)

**Find orchestrator:**
```bash
find src -name "*orchestrator*.js" | grep -v node_modules
```

**Add imports at top of file:**
```javascript
// At the top of orchestrator.js
import { TargetHealthMonitor } from './utils/target-health-monitor.js';
```

**Add to constructor:**
```javascript
export class Orchestrator {
    constructor(config) {
        // ... existing code ...

        // ✅ ADD: Health monitoring setup
        this.healthMonitor = null;
        this.healthCheckEnabled = config.healthCheck !== false;
        this.healthCheckInterval = config.healthCheckInterval || 30000;
        this.stopOnTargetDown = config.stopOnTargetDown !== false;
    }
}
```

**Add initialization method:**
```javascript
// Add this method to Orchestrator class
async initializeHealthMonitoring(target) {
    if (!this.healthCheckEnabled) {
        return;
    }

    console.log('🏥 Initializing target health monitoring...');

    this.healthMonitor = new TargetHealthMonitor(target, {
        maxConsecutiveFailures: 3,
        checkInterval: this.healthCheckInterval,
        timeout: 10000,
    });

    // Initial check
    const initialHealth = await this.healthMonitor.checkHealth();

    if (!initialHealth) {
        throw new Error(`Target ${target} is not reachable`);
    }

    console.log('✅ Target is healthy');

    // Start monitoring
    this.healthMonitor.startMonitoring();
}
```

**Modify the run() or execute() method:**
```javascript
// In the main run/execute method
async run(config) {
    const target = config.target;

    // ✅ ADD: Initialize health monitoring BEFORE starting scan
    await this.initializeHealthMonitoring(target);

    // ... existing scan logic ...
}
```

**Add health check before each agent:**
```javascript
// In runAgent() or wherever agents are executed
async runAgent(agentConfig) {
    // ✅ ADD: Check health before running agent
    if (this.healthMonitor && !this.healthMonitor.isAlive) {
        console.error('\n❌ TARGET IS DOWN');
        console.error('🛑 STOPPING SCAN\n');
        
        if (this.stopOnTargetDown) {
            this.stop();
            throw new Error('Target down - scan stopped');
        }
    }

    // ... existing agent execution code ...
}
```

**Add cleanup in stop():**
```javascript
async stop() {
    // ✅ ADD: Stop health monitoring
    if (this.healthMonitor) {
        this.healthMonitor.stopMonitoring();
        
        const stats = this.healthMonitor.getStats();
        console.log('\n📊 Target Health Summary:');
        console.log(`   Status: ${stats.isAlive ? '✅ UP' : '❌ DOWN'}`);
        console.log(`   Health rate: ${stats.healthRate}`);
    }

    // ... existing stop code ...
}
```

---

### Step 3: Add Config Support (3 minutes)

**In your YAML config files:**

```yaml
# config/juiceshop.yaml
target: http://192.168.1.130:3000
profile: conservative

# ✅ ADD: Health monitoring configuration
health_check:
  enabled: true              # Enable health checks
  interval: 30000            # Check every 30 seconds
  stop_on_down: true         # Stop scan if target crashes
  max_failures: 3            # Consider down after 3 failures
  timeout: 10000             # 10s timeout per health check

pipeline:
  max_concurrency: 1

agents:
  exclude:
    - EnhancedNucleiScanAgent
    - CrawlerAgent
```

---

## Quick Integration (Minimal Changes)

If you can't modify the orchestrator fully, add this **minimal patch**:

**Create: src/local-source-generator/v2/utils/health-check.js**

```javascript
import fetch from 'node-fetch';

let lastCheck = Date.now();
let failureCount = 0;

export async function checkTargetHealth(target) {
    const now = Date.now();
    
    // Check every 30 seconds
    if (now - lastCheck < 30000) {
        return true;
    }
    
    lastCheck = now;
    
    try {
        const response = await fetch(target, { timeout: 10000 });
        
        if (response.status < 500) {
            failureCount = 0;
            return true;
        } else {
            failureCount++;
        }
    } catch (error) {
        failureCount++;
    }
    
    if (failureCount >= 3) {
        console.error('\n❌ TARGET IS DOWN - STOPPING SCAN\n');
        process.exit(1);
    }
    
    return failureCount < 3;
}
```

**Then in orchestrator, add ONE line before each agent:**

```javascript
async runAgent(agentConfig) {
    // ✅ ADD THIS LINE:
    await checkTargetHealth(this.target);
    
    // ... rest of existing code ...
}
```

---

## Testing

### Test 1: Health Check Works

```bash
# Start Juice Shop
docker start <juice-shop>

# Run Shannon
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://192.168.1.130:3000 \
  --config ./config/juiceshop.yaml \
  --output ./test

# Should see:
# 🏥 Initializing target health monitoring...
# ✅ Target is healthy
```

### Test 2: Detects Target Down

```bash
# Start scan
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://192.168.1.130:3000 \
  --config ./config/juiceshop.yaml \
  --output ./test

# In another terminal, KILL Juice Shop
docker stop <juice-shop>

# Shannon should detect within 30-90 seconds:
# ⚠️  Target health check failed (1/3)
# ⚠️  Target health check failed (2/3)
# ⚠️  Target health check failed (3/3)
# ❌ TARGET DOWN DETECTED
# 🛑 STOPPING SCAN
```

### Test 3: Handles Initial Down Target

```bash
# Stop Juice Shop
docker stop <juice-shop>

# Try to run Shannon
LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://192.168.1.130:3000 \
  --config ./config/juiceshop.yaml \
  --output ./test

# Should see:
# 🏥 Initializing target health monitoring...
# ❌ Error: Target http://192.168.1.130:3000 is not reachable
# Scan not started
```

---

## Configuration Options

### Basic (Recommended)

```yaml
health_check:
  enabled: true
  interval: 30000      # Check every 30 seconds
  stop_on_down: true   # Stop immediately when down
  max_failures: 3      # 3 failures = down
```

### Advanced (Wait for Recovery)

```yaml
health_check:
  enabled: true
  interval: 30000
  stop_on_down: false         # Don't stop immediately
  wait_for_recovery: true     # Wait for target to recover
  recovery_timeout: 180000    # Wait max 3 minutes
  max_failures: 3
```

### Aggressive (For Stable Targets)

```yaml
health_check:
  enabled: true
  interval: 60000      # Check every 60 seconds (less often)
  stop_on_down: true
  max_failures: 5      # More tolerant of transient failures
```

### Disabled (Current Behavior)

```yaml
health_check:
  enabled: false
```

---

## Benefits

### Time Saved

**Without health monitoring:**
- Juice Shop crashes at minute 5
- Shannon runs for 30 more minutes against dead target
- **Wasted: 30 minutes**

**With health monitoring:**
- Juice Shop crashes at minute 5
- Shannon detects failure within 90 seconds
- Shannon stops gracefully
- **Wasted: 1.5 minutes**

**Time saved: 28.5 minutes per crash**

### Clearer Feedback

**Before:**
```
[Long pause...]
[Timeouts...]
[More timeouts...]
[Eventually finishes with mostly errors]
```

**After:**
```
❌ TARGET IS DOWN
   Target: http://192.168.1.130:3000
   Consecutive failures: 3
   Last successful check: 90s ago

🛑 STOPPING SCAN - Target is unreachable

Next steps:
1. Check target: curl http://192.168.1.130:3000
2. Restart target if needed
3. Try more conservative settings
```

---

## Alternative: External Script

If you can't modify Shannon's code, wrap it:

**Create: health-wrapper.sh**

```bash
#!/bin/bash

TARGET="$1"
SHANNON_CMD="${@:2}"

# Function to check target
check_target() {
    curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET" | grep -q "^[2-4]"
}

# Initial check
if ! check_target; then
    echo "❌ Target $TARGET is not reachable"
    exit 1
fi

echo "✅ Target is healthy - starting scan"

# Start Shannon in background
$SHANNON_CMD &
SHANNON_PID=$!

# Monitor target while Shannon runs
while kill -0 $SHANNON_PID 2>/dev/null; do
    sleep 30
    
    if ! check_target; then
        echo "❌ TARGET DOWN - Stopping Shannon"
        kill $SHANNON_PID
        exit 1
    fi
done

wait $SHANNON_PID
```

**Usage:**
```bash
chmod +x health-wrapper.sh

./health-wrapper.sh http://192.168.1.130:3000 \
    LSG_ALLOW_PRIVATE=1 ./shannon.mjs generate http://192.168.1.130:3000 \
    --config ./config/juiceshop.yaml \
    --output ./test
```

---

## Summary

### What Gets Added:

1. **TargetHealthMonitor class** - Monitors target health
2. **Integration in orchestrator** - Checks before each agent
3. **Config options** - Control behavior via YAML
4. **Graceful shutdown** - Clear error messages

### Integration Time:

- **Full integration:** 15 minutes
- **Minimal patch:** 5 minutes  
- **External wrapper:** 2 minutes

### Priority:

🔴 **HIGH** - Saves significant time and provides clear feedback

---

## Quick Start (Right Now)

**Minimal viable patch** - add to orchestrator:

```javascript
// At top
import fetch from 'node-fetch';
let healthFailures = 0;

// Before each agent
async function quickHealthCheck(target) {
    try {
        const r = await fetch(target, {timeout: 10000});
        if (r.status < 500) {
            healthFailures = 0;
            return true;
        }
    } catch (e) {}
    
    healthFailures++;
    if (healthFailures >= 3) {
        console.error('\n❌ TARGET DOWN - STOPPING\n');
        process.exit(1);
    }
}

// Use it
async runAgent(agent) {
    await quickHealthCheck(this.target);
    // ... rest of code
}
```

**10 lines of code, massive improvement.**
