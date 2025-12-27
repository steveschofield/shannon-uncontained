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
