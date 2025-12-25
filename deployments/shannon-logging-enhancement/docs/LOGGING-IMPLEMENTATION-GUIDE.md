# Enhanced Logging System - Implementation Guide

## Overview

This guide shows you how to integrate the new enhanced logging system into Shannon. The new system provides:

1. **Distributed Tracing** - Follow requests through the entire pipeline
2. **Detailed Metrics** - Track performance, cost, quality, and reliability
3. **Structured Events** - Machine-readable logs with full context
4. **Beautiful Console Output** - Color-coded, readable terminal output

## Files Created

```
src/logging/
├── trace.js              # Distributed tracing (NEW)
├── metrics.js            # Metrics collection (NEW)
└── unified-logger.js     # Main logger interface (TO BE CREATED)

scripts/
└── analyze-logs.mjs      # Log analysis tool (TO BE CREATED)
```

## Quick Start Integration

### Step 1: Import the Logger

In `shannon.mjs`, add at the top:

```javascript
import UnifiedLogger from './src/logging/unified-logger.js';
```

### Step 2: Initialize Logger

After session creation:

```javascript
// Create session
const sessionId = crypto.randomBytes(8).toString('hex');
const sessionMetadata = {
  id: sessionId,
  webUrl: webUrl,
  repoPath: repoPath,
  hostname: os.hostname()
};

// Initialize logger
const logger = new UnifiedLogger(sessionId, repoPath);
```

### Step 3: Wrap Agent Execution

For each agent that runs, wrap it with tracing:

```javascript
async function runAgent(agentName) {
  // Start trace
  const trace = logger.startTrace(agentName);
  const span = trace.startSpan('agent_execution', { agent: agentName });
  
  try {
    console.log(`\n🚀 Starting ${agentName}...`);
    
    // Run the actual agent
    const result = await executeAgent(agentName);
    
    // Log success
    trace.endSpan(span, 'success', result);
    logger.endTrace('success');
    
    return result;
    
  } catch (error) {
    // Log error
    logger.logEvent({
      type: 'error',
      message: error.message,
      stack: error.stack,
      retryable: error.retryable || false,
      agent: agentName
    });
    
    logger.recordMetric('error', {
      type: error.type || 'unknown',
      message: error.message,
      retryable: error.retryable || false,
      agent: agentName
    });
    
    trace.endSpan(span, 'error', { error: error.message });
    logger.endTrace('error');
    
    throw error;
  }
}
```

### Step 4: Log Tool Execution

When running external tools (nmap, nuclei, etc.):

```javascript
async function runTool(toolName, args) {
  const startTime = Date.now();
  
  // Log tool start
  logger.logEvent({
    type: 'tool_start',
    tool: toolName,
    args: args
  });
  
  try {
    const result = await $`${toolName} ${args}`;
    const duration = Date.now() - startTime;
    
    // Log tool success
    logger.logEvent({
      type: 'tool_end',
      tool: toolName,
      success: true,
      duration: duration
    });
    
    logger.recordMetric('tool_execution', {
      tool: toolName,
      duration: duration,
      success: true,
      outputSize: result.stdout.length
    });
    
    return result;
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Log tool failure
    logger.logEvent({
      type: 'tool_end',
      tool: toolName,
      success: false,
      duration: duration,
      error: error.message
    });
    
    logger.recordMetric('tool_execution', {
      tool: toolName,
      duration: duration,
      success: false,
      error: error.message
    });
    
    throw error;
  }
}
```

### Step 5: Log HTTP Requests

When making HTTP requests (especially in blackbox mode):

```javascript
async function makeHttpRequest(url, options = {}) {
  const startTime = Date.now();
  
  try {
    const response = await fetch(url, options);
    const duration = Date.now() - startTime;
    const body = await response.text();
    
    // Log HTTP request
    logger.logEvent({
      type: 'http_request',
      method: options.method || 'GET',
      url: url,
      statusCode: response.status,
      duration: duration,
      size: body.length
    });
    
    logger.recordMetric('http_request', {
      url: url,
      method: options.method || 'GET',
      statusCode: response.status,
      duration: duration,
      size: body.length
    });
    
    return { response, body };
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.logEvent({
      type: 'http_request',
      method: options.method || 'GET',
      url: url,
      statusCode: 0,
      duration: duration,
      error: error.message
    });
    
    logger.recordMetric('http_request', {
      url: url,
      method: options.method || 'GET',
      statusCode: 0,
      duration: duration,
      error: error.message
    });
    
    throw error;
  }
}
```

### Step 6: Log Findings

When a vulnerability is discovered:

```javascript
function recordFinding(vulnerability) {
  logger.logEvent({
    type: 'finding',
    vulnerability: vulnerability.type,
    severity: vulnerability.severity,
    confidence: vulnerability.confidence,
    agent: currentAgentName
  });
  
  logger.recordMetric('finding', {
    type: vulnerability.type,
    severity: vulnerability.severity,
    confidence: vulnerability.confidence,
    agent: currentAgentName,
    validated: false  // Will be updated during exploitation
  });
}
```

### Step 7: Close Logger at End of Session

At the very end of `shannon.mjs`:

```javascript
// Save metrics and close logger
logger.close();

console.log('\n📊 Session complete. View logs at:');
console.log(`   Traces: ${repoPath}/deliverables/logs/traces/`);
console.log(`   Metrics: ${repoPath}/deliverables/logs/metrics/`);
console.log(`   Events: ${repoPath}/deliverables/logs/events/events.ndjson`);
```

## Using the Log Analyzer

After a scan completes, analyze the logs:

```bash
chmod +x scripts/analyze-logs.mjs
./scripts/analyze-logs.mjs ./deliverables/logs
```

This will show:
- Event distribution
- HTTP request stats (status codes, latencies)
- Tool execution performance
- Error patterns
- Finding breakdown

## What the Logs Look Like

### Console Output

```
[10:30:15] [a3f2b1c9] 🚀 Starting injection-vuln
[10:30:16] [a3f2b1c9]   🔧 Running nmap...
[10:30:21] [a3f2b1c9]   ✓ nmap completed in 5234ms
[10:30:21] [a3f2b1c9]   GET http://target.com/api/users → 200 (234ms)
[10:30:22] [a3f2b1c9]   🤖 LLM claude-sonnet-4: 5420 tokens, $0.0271
[10:30:25] [a3f2b1c9]   🔍 Finding: CRITICAL sql_injection (confidence: high)
[10:30:25] [a3f2b1c9] ✓ Completed injection-vuln in 10.2s
```

### Events Log (NDJSON)

```json
{"timestamp":"2025-01-15T10:30:15.123Z","sessionId":"a3f2b1c9","traceId":"f4e3d2c1","type":"trace_start","agentName":"injection-vuln"}
{"timestamp":"2025-01-15T10:30:16.456Z","sessionId":"a3f2b1c9","traceId":"f4e3d2c1","type":"tool_start","tool":"nmap"}
{"timestamp":"2025-01-15T10:30:21.789Z","sessionId":"a3f2b1c9","traceId":"f4e3d2c1","type":"tool_end","tool":"nmap","success":true,"duration":5234}
```

### Metrics Summary

```
# Shannon Metrics Summary

## Performance

### HTTP Requests
- Total: 245
- Success Rate: 94.29%
- Avg Latency: 234ms
- P95 Latency: 567ms
- P99 Latency: 1234ms
- Data Transferred: 12.4 MB

### Tool Execution
- nmap: 1 runs, 100.00% success, 5234ms avg
- nuclei: 1 runs, 100.00% success, 12456ms avg
- sqlmap: 3 runs, 66.67% success, 8934ms avg

## Cost

### LLM API Usage
- Total Calls: 15
- Total Tokens: 124,560
- Total Cost: $0.62
- Avg Cost/Call: $0.0413

## Quality

### Findings
- Total: 12
- Validated: 8
- False Positives: 1
- Validation Rate: 88.89%

### By Severity
- critical: 3
- high: 5
- medium: 4

## Reliability

### Errors
- Total: 4
- Retryable: 3
- Fatal: 1
```

## Trace Visualization

Each trace file shows the complete flow:

```json
{
  "traceId": "f4e3d2c1b5a69874",
  "sessionId": "a3f2b1c9",
  "agentName": "injection-vuln",
  "duration": 10234,
  "spans": [
    {
      "spanId": "ab12cd34",
      "name": "agent_execution",
      "duration": 10234,
      "status": "success",
      "events": [
        {"name": "tool_execution", "data": {"tool": "nmap"}},
        {"name": "http_request", "data": {"url": "..."}},
        {"name": "llm_call", "data": {"tokens": 5420}}
      ]
    }
  ]
}
```

## Benefits

### For Debugging
- **Find slowest operations**: `cat logs/metrics/metrics.json | jq '.raw_metrics.performance.tools'`
- **Find error patterns**: `grep '"type":"error"' logs/events/events.ndjson | jq .message`
- **Trace specific request**: `grep 'traceId":"abc123"' logs/events/events.ndjson`

### For Optimization
- **Identify bottlenecks**: Check which tools/agents take longest
- **Reduce costs**: See which agents use most LLM tokens
- **Improve accuracy**: Track false positive rates by agent

### For Reporting
- **Show to clients**: Metrics summary proves thoroughness
- **Internal metrics**: Track improvement over time
- **Cost tracking**: Bill clients accurately

## Next Steps

1. Create the `unified-logger.js` file (I can do this)
2. Create the `analyze-logs.mjs` script (I can do this)
3. Integrate into `shannon.mjs` (follow steps above)
4. Test on a small target first
5. Review logs and iterate

Would you like me to create the remaining files?
