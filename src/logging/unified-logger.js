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
    this.currentTrace = null; // kept for backward compatibility (last started)
    this.activeTraces = new Map(); // traceId -> TraceContext
    this.agentTraceMap = new Map(); // agentName -> [traceIds]
    
    // Create log directories
    this.logsDir = path.join(outputDir, 'deliverables', 'logs');
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
    const trace = new TraceContext(this.sessionId, agentName);
    this.currentTrace = trace;
    this.traces.push(trace);

    // Track active traces
    this.activeTraces.set(trace.traceId, trace);
    const list = this.agentTraceMap.get(agentName) || [];
    list.push(trace.traceId);
    this.agentTraceMap.set(agentName, list);

    this.logEvent({
      type: 'trace_start',
      traceId: trace.traceId,
      agentName
    });

    return trace;
  }

  /**
   * End a trace safely in concurrent environments
   */
  endTrace(identifierOrStatus = 'success', maybeStatus) {
    // Backward compatible usage: endTrace('success') ends the last currentTrace
    if (maybeStatus === undefined && (identifierOrStatus === 'success' || identifierOrStatus === 'error')) {
      const status = identifierOrStatus;
      const trace = this.currentTrace;
      if (!trace) return;
      this.#finalizeTrace(trace, status);
      return;
    }

    // New usage: endTrace(traceIdOrAgentName, status)
    const identifier = identifierOrStatus;
    const status = maybeStatus || 'success';

    let trace = null;
    // Try by traceId
    if (this.activeTraces.has(identifier)) {
      trace = this.activeTraces.get(identifier);
    } else if (this.agentTraceMap.has(identifier)) {
      // identifier treated as agentName; pop the latest
      const list = this.agentTraceMap.get(identifier);
      const lastId = list && list.length > 0 ? list.pop() : null;
      if (lastId) {
        trace = this.activeTraces.get(lastId) || null;
        if (list && list.length === 0) this.agentTraceMap.delete(identifier);
        else if (list) this.agentTraceMap.set(identifier, list);
      }
    }

    if (!trace) return; // Nothing to end
    this.#finalizeTrace(trace, status);
  }

  #finalizeTrace(traceCtx, status) {
    try {
      const exported = traceCtx.export();
      const traceFile = path.join(this.tracesDir, `${traceCtx.agentName}-${traceCtx.traceId}.json`);
      fs.writeFileSync(traceFile, JSON.stringify(exported, null, 2));

      this.logEvent({
        type: 'trace_end',
        traceId: traceCtx.traceId,
        agentName: traceCtx.agentName,
        duration: exported.duration,
        status
      });
    } finally {
      // Remove from active maps
      this.activeTraces.delete(traceCtx.traceId);
      const list = this.agentTraceMap.get(traceCtx.agentName) || [];
      const idx = list.indexOf(traceCtx.traceId);
      if (idx >= 0) list.splice(idx, 1);
      if (list.length === 0) this.agentTraceMap.delete(traceCtx.agentName);
      else this.agentTraceMap.set(traceCtx.agentName, list);
      // Do not null currentTrace; keep last for backward compatibility
    }
  }

  /** Lookup active trace by agent name */
  getActiveTraceForAgent(agentName) {
    const list = this.agentTraceMap.get(agentName) || [];
    const lastId = list[list.length - 1];
    return lastId ? this.activeTraces.get(lastId) : null;
  }

  /**
   * Log a structured event
   */
  logEvent(event) {
    const enrichedEvent = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      traceId: event.traceId || this.currentTrace?.traceId,
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
        // Don't log everything to console, just to file
        break;
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
