/**
 * Analysis Agents - Index (UPDATED FOR BLACKBOX MODE)
 * 
 * Added: AuthFlowDetector - Critical for blackbox authentication testing
 */

import { ArchitectInferAgent } from './architect-infer-agent.js';
import { AuthFlowAnalyzer } from './auth-flow-analyzer.js';
import { AuthFlowDetector } from './auth-flow-detector.js'; // NEW - BLACKBOX AUTH DETECTION
import { DataFlowMapper } from './data-flow-mapper.js';
import { VulnHypothesizer } from './vuln-hypothesizer.js';
import { BusinessLogicAgent } from './business-logic-agent.js';
import { SecurityHeaderAnalyzer } from './security-header-analyzer.js';
import { TLSAnalyzer } from './tls-analyzer.js';
import { PassiveSecurityAgent } from './passive-security-agent.js';
import { APISchemaGenerator } from './api-schema-generator.js';
import { JSSecurityAgent } from './js-security-agent.js';

export {
    ArchitectInferAgent,
    AuthFlowAnalyzer,
    AuthFlowDetector, // NEW
    DataFlowMapper,
    VulnHypothesizer,
    BusinessLogicAgent,
    SecurityHeaderAnalyzer,
    TLSAnalyzer,
    PassiveSecurityAgent,
    APISchemaGenerator,
    JSSecurityAgent,
};

/**
 * Register all analysis agents with orchestrator
 * @param {Orchestrator} orchestrator - Orchestrator instance
 */
export function registerAnalysisAgents(orchestrator) {
    // CRITICAL: Run AuthFlowDetector early for blackbox mode
    orchestrator.registerAgent(new AuthFlowDetector());  // NEW - Run after recon, before vuln analysis
    
    // Passive analysis of collected responses (no new requests)
    orchestrator.registerAgent(new PassiveSecurityAgent());
    
    // Generate API schema from discovered endpoints/responses
    orchestrator.registerAgent(new APISchemaGenerator());
    
    orchestrator.registerAgent(new ArchitectInferAgent());
    orchestrator.registerAgent(new AuthFlowAnalyzer());
    orchestrator.registerAgent(new DataFlowMapper());
    orchestrator.registerAgent(new JSSecurityAgent());
    orchestrator.registerAgent(new VulnHypothesizer());
    orchestrator.registerAgent(new BusinessLogicAgent());
    orchestrator.registerAgent(new SecurityHeaderAnalyzer());
    orchestrator.registerAgent(new TLSAnalyzer());
}
