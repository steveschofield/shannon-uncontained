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
      if (req.duration) latencies.push(req.duration);
    }
    
    console.log('Status Codes:');
    for (const [code, count] of Object.entries(statusCodes).sort((a, b) => b[1] - a[1])) {
      const color = code >= 400 ? chalk.red : chalk.green;
      console.log(color(`  ${code}: ${count}`));
    }
    
    if (latencies.length > 0) {
      console.log('\nLatency Stats:');
      console.log(`  Min: ${Math.min(...latencies)}ms`);
      console.log(`  Max: ${Math.max(...latencies)}ms`);
      console.log(`  Avg: ${(latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(0)}ms`);
      console.log(`  P95: ${percentile(latencies, 0.95).toFixed(0)}ms`);
    }
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
      byType[finding.vulnerability || finding.type] = (byType[finding.vulnerability || finding.type] || 0) + 1;
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
  const sortedAgents = Object.entries(agentDurations).sort((a, b) => {
    const avgA = a[1].reduce((sum, d) => sum + d, 0) / a[1].length;
    const avgB = b[1].reduce((sum, d) => sum + d, 0) / b[1].length;
    return avgB - avgA;
  });
  
  for (const [agent, durations] of sortedAgents) {
    const avg = durations.reduce((sum, d) => sum + d, 0) / durations.length;
    const max = Math.max(...durations);
    console.log(`  ${agent}: avg ${(avg / 1000).toFixed(1)}s, max ${(max / 1000).toFixed(1)}s (${durations.length} runs)`);
  }
}

function percentile(arr, p) {
  if (arr.length === 0) return 0;
  const sorted = arr.slice().sort((a, b) => a - b);
  const index = Math.ceil(sorted.length * p) - 1;
  return sorted[index];
}

// Main
const logsDir = process.argv[2] || './deliverables/logs';

if (!fs.existsSync(logsDir)) {
  console.error(chalk.red(`Logs directory not found: ${logsDir}`));
  console.log('\nUsage: ./scripts/analyze-logs.mjs [logs-directory]');
  console.log('Example: ./scripts/analyze-logs.mjs ./deliverables/logs');
  process.exit(1);
}

const eventsLog = path.join(logsDir, 'events', 'events.ndjson');
const tracesDir = path.join(logsDir, 'traces');

if (fs.existsSync(eventsLog)) {
  analyzeEventLog(eventsLog);
} else {
  console.log(chalk.yellow(`No events log found at ${eventsLog}`));
}

if (fs.existsSync(tracesDir)) {
  analyzeTraces(tracesDir);
} else {
  console.log(chalk.yellow(`No traces directory found at ${tracesDir}`));
}

console.log(chalk.blue('\n=== Analysis Complete ===\n'));
