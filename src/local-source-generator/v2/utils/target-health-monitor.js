/**
 * TargetHealthMonitor
 * 
 * Periodically checks target reachability and records health stats.
 * Intended to stop the pipeline quickly when the target goes down.
 */

import fetch from 'node-fetch';

export class TargetHealthMonitor {
    constructor(target, options = {}) {
        this.target = target;
        this.isAlive = true;
        this.consecutiveFailures = 0;
        this.maxConsecutiveFailures = options.maxConsecutiveFailures ?? 3;
        this.checkInterval = options.checkInterval ?? 30000; // 30s
        this.timeout = options.timeout ?? 10000; // 10s
        this.waitForRecovery = options.waitForRecovery === true;
        this.recoveryTimeout = options.recoveryTimeout ?? 180000; // 3m

        this.checkHistory = [];
        this.lastSuccessfulCheck = Date.now();

        this.monitoringActive = false;
        this.monitorInterval = null;
    }

    startMonitoring() {
        if (this.monitoringActive) return;
        this.monitoringActive = true;
        this.checkHealth(); // initial async check
        this.monitorInterval = setInterval(() => {
            this.checkHealth();
        }, this.checkInterval);
    }

    stopMonitoring() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }
        this.monitoringActive = false;
    }

    async checkHealth() {
        try {
            const start = Date.now();
            const response = await fetch(this.target, {
                method: 'GET',
                timeout: this.timeout,
                headers: { 'User-Agent': 'Shannon-HealthCheck/1.0' }
            });
            const responseTime = Date.now() - start;
            const healthy = response.status < 500;

            if (healthy) {
                this.consecutiveFailures = 0;
                this.isAlive = true;
                this.lastSuccessfulCheck = Date.now();
                this.recordCheck({ healthy: true, status: response.status, responseTime });
                return true;
            }

            return this.handleFailure(`HTTP ${response.status}`, response.status);
        } catch (err) {
            return this.handleFailure(err.message);
        }
    }

    handleFailure(reason, status = null) {
        this.consecutiveFailures += 1;
        this.recordCheck({ healthy: false, reason, status });

        if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
            this.isAlive = false;
        }

        return this.isAlive;
    }

    recordCheck(result) {
        this.checkHistory.push({ timestamp: Date.now(), ...result });
        if (this.checkHistory.length > 100) {
            this.checkHistory.shift();
        }
    }

    getTimeSinceLastSuccess() {
        const elapsed = Date.now() - this.lastSuccessfulCheck;
        const seconds = Math.floor(elapsed / 1000);
        const minutes = Math.floor(seconds / 60);
        return minutes > 0 ? `${minutes}m ${seconds % 60}s ago` : `${seconds}s ago`;
    }

    getStats() {
        const window = this.checkHistory.slice(-10);
        const healthy = window.filter(c => c.healthy).length;
        const rate = window.length ? (healthy / window.length * 100).toFixed(1) : '100.0';

        return {
            isAlive: this.isAlive,
            consecutiveFailures: this.consecutiveFailures,
            healthRate: `${rate}%`,
            lastSuccessfulCheck: this.getTimeSinceLastSuccess(),
            totalChecks: this.checkHistory.length,
        };
    }

    async waitForRecovery(maxWaitTime = this.recoveryTimeout) {
        const start = Date.now();
        while (Date.now() - start < maxWaitTime) {
            const healthy = await this.checkHealth();
            if (healthy && this.isAlive) {
                return true;
            }
            await new Promise(r => setTimeout(r, 5000));
        }
        return false;
    }
}

export default TargetHealthMonitor;
