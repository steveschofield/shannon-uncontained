/**
 * Vulnerability Analysis Agents - Index (UPDATED FOR BLACKBOX MODE)
 * 
 * Added:
 * - ParameterDiscoveryAgent - Find injection points without source code
 * - NoSQLInjectionAgent - Detect MongoDB/Redis injection (Juice Shop improvement)
 * - DOMXSSAgent - Detect client-side XSS in modern SPAs
 */

// Import existing agents (adjust paths as needed based on your structure)
// These are placeholders - replace with actual imports from your codebase

// NEW BLACKBOX AGENTS
import { ParameterDiscoveryAgent } from './parameter-discovery-agent.js';
import { NoSQLInjectionAgent } from './nosql-injection-agent.js';
import { DOMXSSAgent } from './dom-xss-agent.js';
import { BusinessLogicFuzzer } from './business-logic-fuzzer.js';
import { CSRFDetector } from './csrf-detector.js';
import { SSRFDetector } from './ssrf-detector.js';
import { GraphQLTester } from './graphql-tester.js';

export {
    ParameterDiscoveryAgent,
    NoSQLInjectionAgent,
    DOMXSSAgent,
    BusinessLogicFuzzer,
    CSRFDetector,
    SSRFDetector,
    GraphQLTester,
};

/**
 * Register all vulnerability analysis agents with orchestrator
 * @param {Orchestrator} orchestrator - Orchestrator instance
 */
export function registerVulnAnalysisAgents(orchestrator) {
    // CRITICAL: ParameterDiscoveryAgent runs FIRST to find injection points
    orchestrator.registerAgent(new ParameterDiscoveryAgent());  // NEW - Find injection points
    
    // Then specialized vulnerability agents
    orchestrator.registerAgent(new NoSQLInjectionAgent());      // NEW - NoSQL injection
    orchestrator.registerAgent(new DOMXSSAgent());              // NEW - DOM XSS
    orchestrator.registerAgent(new BusinessLogicFuzzer());      // NEW - Business logic flaws
    orchestrator.registerAgent(new CSRFDetector());             // NEW - CSRF detection
    orchestrator.registerAgent(new SSRFDetector());             // NEW - SSRF detection
    orchestrator.registerAgent(new GraphQLTester());            // NEW - GraphQL tests
    
    // Existing agents would be registered here
    // orchestrator.registerAgent(new SQLInjectionAgent());
    // orchestrator.registerAgent(new XSSAgent());
    // etc.
}
