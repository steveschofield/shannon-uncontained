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

export {
    ArchitectInferAgent,
    AuthFlowAnalyzer,
    AuthFlowDetector, // NEW
    DataFlowMapper,
    VulnHypothesizer,
    BusinessLogicAgent,
    SecurityHeaderAnalyzer,
    TLSAnalyzer
};

/**
 * Register all analysis agents with orchestrator
 * @param {Orchestrator} orchestrator - Orchestrator instance
 */
export function registerAnalysisAgents(orchestrator) {
    // CRITICAL: Run AuthFlowDetector early for blackbox mode
    orchestrator.registerAgent(new AuthFlowDetector());  // NEW - Run after recon, before vuln analysis
    
    orchestrator.registerAgent(new ArchitectInferAgent());
    orchestrator.registerAgent(new AuthFlowAnalyzer());
    orchestrator.registerAgent(new DataFlowMapper());
    orchestrator.registerAgent(new VulnHypothesizer());
    orchestrator.registerAgent(new BusinessLogicAgent());
    orchestrator.registerAgent(new SecurityHeaderAnalyzer());
    orchestrator.registerAgent(new TLSAnalyzer());
}
