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
import { OpenRedirectAgent } from './open-redirect-agent.js';
import { SSTIAgent } from './ssti-agent.js';
import { JWTAnalyzerAgent } from './jwt-analyzer-agent.js';
import { CachePoisoningProbeAgent } from './cache-poisoning-probe-agent.js';
import { RequestSmugglingDetector } from './request-smuggling-detector.js';
import { JWTPolicyCheckerAgent } from './jwt-policy-checker-agent.js';
import { CacheDeceptionAnalyzerAgent } from './cache-deception-analyzer-agent.js';
import { XXEUploadAgent } from './xxe-upload-agent.js';
import { OAuthMisconfigAgent } from './oauth-misconfig-agent.js';
import { IDORProbeAgent } from './idor-probe-agent.js';

export {
    ParameterDiscoveryAgent,
    NoSQLInjectionAgent,
    DOMXSSAgent,
    BusinessLogicFuzzer,
    CSRFDetector,
    SSRFDetector,
    GraphQLTester,
    OpenRedirectAgent,
    SSTIAgent,
    JWTAnalyzerAgent,
    CachePoisoningProbeAgent,
    RequestSmugglingDetector,
    JWTPolicyCheckerAgent,
    CacheDeceptionAnalyzerAgent,
    XXEUploadAgent,
    OAuthMisconfigAgent,
    IDORProbeAgent,
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
    orchestrator.registerAgent(new OpenRedirectAgent());        // NEW - Open redirect detection
    orchestrator.registerAgent(new SSTIAgent());                // NEW - SSTI detection
    orchestrator.registerAgent(new JWTAnalyzerAgent());         // NEW - JWT analysis
    orchestrator.registerAgent(new CachePoisoningProbeAgent()); // NEW - Cache poisoning probe
    orchestrator.registerAgent(new RequestSmugglingDetector()); // NEW - Request smuggling heuristics
    orchestrator.registerAgent(new JWTPolicyCheckerAgent());    // NEW - OIDC policy checks
    orchestrator.registerAgent(new CacheDeceptionAnalyzerAgent());// NEW - Cache deception & Vary
    orchestrator.registerAgent(new XXEUploadAgent());           // NEW - XXE safe upload probes
    orchestrator.registerAgent(new OAuthMisconfigAgent());      // NEW - OAuth redirect/scope checks
    orchestrator.registerAgent(new IDORProbeAgent());           // NEW - IDOR heuristic probe
    
    // Existing agents would be registered here
    // orchestrator.registerAgent(new SQLInjectionAgent());
    // orchestrator.registerAgent(new XSSAgent());
    // etc.
}
