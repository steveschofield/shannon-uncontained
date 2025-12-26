/**
 * Target Health Monitor
 * 
 * Detects when target goes down during scan and stops gracefully.
 * 
 * Integrate this into Shannon's orchestrator to prevent running agents
 * against crashed targets.
 */

import fetch from 'node-fetch';

export class TargetHealthMonitor {
    constructor(target, options = {}) {
        this.target = target;
        this.isAlive = true;
        this.consecutiveFailures = 0;
        this.maxConsecutiveFailures = options.maxConsecutiveFailures || 3;
        this.checkInterval = options.checkInterval || 30000; // 30 seconds
        this.timeout = options.timeout || 10000; // 10 seconds
        
        // Health check history
        this.checkHistory = [];
        this.lastSuccessfulCheck = Date.now();
        
        // Monitoring
        this.monitoringActive = false;
        this.monitorInterval = null;
    }

    /**
     * Start continuous health monitoring
     */
    startMonitoring() {
        if (this.monitoringActive) {
            return;
        }

        this.monitoringActive = true;
        console.log(`🏥 Starting target health monitoring: ${this.target}`);

        // Initial check
        this.checkHealth();

        // Set up interval
        this.monitorInterval = setInterval(() => {
            this.checkHealth();
        }, this.checkInterval);
    }

    /**
     * Stop health monitoring
     */
    stopMonitoring() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }
        this.monitoringActive = false;
        console.log(`🏥 Stopped target health monitoring`);
    }

    /**
     * Check if target is alive
     */
    async checkHealth() {
        try {
            const startTime = Date.now();
            
            const response = await fetch(this.target, {
                method: 'GET',
                timeout: this.timeout,
                headers: {
                    'User-Agent': 'Shannon-HealthCheck/1.0',
                },
            });

            const responseTime = Date.now() - startTime;

            // Check if response is valid
            const isHealthy = response.status < 500;

            if (isHealthy) {
                // Target is alive
                this.consecutiveFailures = 0;
                this.isAlive = true;
                this.lastSuccessfulCheck = Date.now();

                this.recordCheck({
                    timestamp: Date.now(),
                    healthy: true,
                    status: response.status,
                    responseTime,
                });

                return true;

            } else {
                // Server error (5xx)
                return this.handleFailure('Server error', response.status);
            }

        } catch (error) {
            return this.handleFailure(error.message);
        }
    }

    /**
     * Handle health check failure
     */
    handleFailure(reason, status = null) {
        this.consecutiveFailures++;

        this.recordCheck({
            timestamp: Date.now(),
            healthy: false,
            reason,
            status,
        });

        if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
            // Target is down
            this.isAlive = false;
            
            console.error('❌ TARGET DOWN DETECTED');
            console.error(`   Target: ${this.target}`);
            console.error(`   Consecutive failures: ${this.consecutiveFailures}`);
            console.error(`   Last successful check: ${this.getTimeSinceLastSuccess()}`);
            console.error('');
            console.error('🛑 STOPPING SCAN - Target is unreachable');

            return false;
        } else {
            console.warn(`⚠️  Target health check failed (${this.consecutiveFailures}/${this.maxConsecutiveFailures})`);
            console.warn(`   Reason: ${reason}`);
            return true; // Still considered alive until threshold
        }
    }

    /**
     * Record health check result
     */
    recordCheck(result) {
        this.checkHistory.push(result);

        // Keep only last 100 checks
        if (this.checkHistory.length > 100) {
            this.checkHistory.shift();
        }
    }

    /**
     * Get time since last successful check
     */
    getTimeSinceLastSuccess() {
        const elapsed = Date.now() - this.lastSuccessfulCheck;
        const seconds = Math.floor(elapsed / 1000);
        const minutes = Math.floor(seconds / 60);

        if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s ago`;
        } else {
            return `${seconds}s ago`;
        }
    }

    /**
     * Get health statistics
     */
    getStats() {
        const recentChecks = this.checkHistory.slice(-10);
        const healthyChecks = recentChecks.filter(c => c.healthy).length;
        const healthRate = recentChecks.length > 0
            ? (healthyChecks / recentChecks.length * 100).toFixed(1)
            : 100;

        return {
            isAlive: this.isAlive,
            consecutiveFailures: this.consecutiveFailures,
            healthRate: `${healthRate}%`,
            lastSuccessfulCheck: this.getTimeSinceLastSuccess(),
            totalChecks: this.checkHistory.length,
        };
    }

    /**
     * Wait for target to come back up
     */
    async waitForRecovery(maxWaitTime = 300000) {
        console.log('⏳ Waiting for target to recover...');
        
        const startTime = Date.now();
        const checkInterval = 5000; // Check every 5 seconds

        while (Date.now() - startTime < maxWaitTime) {
            const healthy = await this.checkHealth();

            if (healthy && this.isAlive) {
                console.log('✅ Target recovered!');
                return true;
            }

            console.log(`   Still down... (${Math.floor((Date.now() - startTime) / 1000)}s elapsed)`);
            await this.delay(checkInterval);
        }

        console.error('❌ Target did not recover within timeout');
        return false;
    }

    /**
     * Delay helper
     */
    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * Integration with Shannon Orchestrator
 */
export class TargetHealthIntegration {
    constructor(orchestrator, target, options = {}) {
        this.orchestrator = orchestrator;
        this.healthMonitor = new TargetHealthMonitor(target, options);
        this.pauseOnFailure = options.pauseOnFailure !== false;
        this.stopOnFailure = options.stopOnFailure !== false;
    }

    /**
     * Start monitoring with orchestrator integration
     */
    async start() {
        // Initial health check
        const initialHealth = await this.healthMonitor.checkHealth();

        if (!initialHealth) {
            throw new Error('Target is not reachable - cannot start scan');
        }

        // Start continuous monitoring
        this.healthMonitor.startMonitoring();

        // Hook into orchestrator events
        this.setupOrchestorHooks();
    }

    /**
     * Setup hooks into orchestrator
     */
    setupOrchestorHooks() {
        // Before each agent runs
        this.orchestrator.on('agent:before', async (agent) => {
            if (!this.healthMonitor.isAlive) {
                console.error('🛑 Target is down - skipping agent:', agent.name);
                
                if (this.pauseOnFailure) {
                    console.log('⏳ Attempting target recovery...');
                    const recovered = await this.healthMonitor.waitForRecovery();
                    
                    if (!recovered && this.stopOnFailure) {
                        this.orchestrator.stop();
                        throw new Error('Target down - scan stopped');
                    }
                }
            }
        });

        // After each agent completes
        this.orchestrator.on('agent:after', async (agent, result) => {
            // Quick health check after each agent
            if (!this.healthMonitor.isAlive) {
                console.error('❌ Target went down during agent execution:', agent.name);
                
                if (this.stopOnFailure) {
                    this.orchestrator.stop();
                }
            }
        });

        // On orchestrator stop
        this.orchestrator.on('stop', () => {
            this.healthMonitor.stopMonitoring();
        });
    }

    /**
     * Stop monitoring
     */
    stop() {
        this.healthMonitor.stopMonitoring();
    }

    /**
     * Get health stats
     */
    getStats() {
        return this.healthMonitor.getStats();
    }
}

export default TargetHealthMonitor;
