/**
 * Orchestrator Patch - Add Target Health Monitoring
 * 
 * This patch adds target health monitoring to Shannon's orchestrator.
 * Apply this to prevent running agents against crashed targets.
 * 
 * Location: src/local-source-generator/v2/orchestrator.js
 */

import { TargetHealthMonitor } from './target-health-monitor.js';

/**
 * Add this to the Orchestrator class
 */
export class OrchestratorWithHealthMonitoring {
    constructor(config) {
        // ... existing constructor code ...

        // ✅ NEW: Initialize health monitor
        this.healthMonitor = null;
        this.healthCheckEnabled = config.healthCheck !== false;
        this.healthCheckInterval = config.healthCheckInterval || 30000; // 30s
        this.stopOnTargetDown = config.stopOnTargetDown !== false;
    }

    /**
     * ✅ NEW: Initialize health monitoring for target
     */
    async initializeHealthMonitoring(target) {
        if (!this.healthCheckEnabled) {
            console.log('ℹ️  Target health monitoring disabled');
            return;
        }

        console.log('🏥 Initializing target health monitoring...');

        this.healthMonitor = new TargetHealthMonitor(target, {
            maxConsecutiveFailures: 3,
            checkInterval: this.healthCheckInterval,
            timeout: 10000,
        });

        // Initial check
        const initialHealth = await this.healthMonitor.checkHealth();

        if (!initialHealth) {
            throw new Error(`Target ${target} is not reachable - cannot start scan`);
        }

        console.log('✅ Target is healthy - starting scan');

        // Start monitoring
        this.healthMonitor.startMonitoring();
    }

    /**
     * ✅ MODIFIED: Run stage with health checks
     */
    async runStage(stage) {
        console.log(`\n⚡ Stage: ${stage.name}`);

        const agents = stage.agents;
        const results = [];

        for (const agentConfig of agents) {
            // ✅ NEW: Check target health before each agent
            if (this.healthMonitor && !this.healthMonitor.isAlive) {
                console.error('');
                console.error('❌ TARGET IS DOWN');
                console.error('   The target stopped responding during the scan.');
                console.error('');
                
                if (this.stopOnTargetDown) {
                    console.error('🛑 STOPPING SCAN');
                    console.error('');
                    console.error('   What happened:');
                    console.error('   - Target became unreachable');
                    console.error('   - Likely crashed or overloaded');
                    console.error('   - Continuing would waste time');
                    console.error('');
                    console.error('   Next steps:');
                    console.error('   1. Check target: curl http://your-target');
                    console.error('   2. Restart target if needed');
                    console.error('   3. Try more conservative settings');
                    console.error('   4. Re-run Shannon with --profile conservative');
                    console.error('');

                    // Stop the scan
                    this.stop();
                    break;
                }
            }

            // Run agent
            try {
                const result = await this.runAgent(agentConfig);
                results.push(result);

            } catch (error) {
                console.error(`Agent ${agentConfig.name} failed:`, error.message);
                
                // ✅ NEW: Check if failure was due to target being down
                if (this.healthMonitor) {
                    const stillAlive = await this.healthMonitor.checkHealth();
                    
                    if (!stillAlive) {
                        console.error('❌ Agent failed because target is down');
                        
                        if (this.stopOnTargetDown) {
                            console.error('🛑 Stopping scan due to target failure');
                            this.stop();
                            break;
                        }
                    }
                }

                results.push({ error: error.message });
            }
        }

        return results;
    }

    /**
     * ✅ MODIFIED: Stop with cleanup
     */
    async stop() {
        console.log('\n🛑 Stopping orchestrator...');

        // Stop health monitoring
        if (this.healthMonitor) {
            this.healthMonitor.stopMonitoring();
            
            // Print final health stats
            const stats = this.healthMonitor.getStats();
            console.log('\n📊 Target Health Summary:');
            console.log(`   Status: ${stats.isAlive ? '✅ UP' : '❌ DOWN'}`);
            console.log(`   Health rate: ${stats.healthRate}`);
            console.log(`   Total checks: ${stats.totalChecks}`);
            if (!stats.isAlive) {
                console.log(`   Last seen: ${stats.lastSuccessfulCheck}`);
            }
        }

        // ... existing stop code ...
    }
}

/**
 * ✅ NEW: Add configuration option to shannon.mjs or config files
 */
export const DEFAULT_ORCHESTRATOR_CONFIG = {
    // ... existing config ...

    // Health monitoring
    healthCheck: true,                // Enable target health monitoring
    healthCheckInterval: 30000,       // Check every 30 seconds
    stopOnTargetDown: true,           // Stop scan if target goes down
    waitForRecovery: false,           // Wait for target to recover (vs stop immediately)
    recoveryTimeout: 300000,          // Max time to wait for recovery (5 min)
};

/**
 * Usage in config file (YAML)
 */
/*
# config/juiceshop.yaml
target: http://192.168.1.130:3000
profile: conservative

# Target health monitoring
health_check:
  enabled: true
  interval: 30000           # Check every 30 seconds
  stop_on_down: true        # Stop scan if target crashes
  wait_for_recovery: true   # Try to wait for target to come back
  recovery_timeout: 180000  # Wait max 3 minutes for recovery
  max_failures: 3           # Consider down after 3 consecutive failures

pipeline:
  max_concurrency: 1

agents:
  exclude:
    - EnhancedNucleiScanAgent
    - CrawlerAgent
*/
