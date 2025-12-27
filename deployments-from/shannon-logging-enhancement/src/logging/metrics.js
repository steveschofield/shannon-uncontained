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
