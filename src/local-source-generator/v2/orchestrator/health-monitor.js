/**
 * PipelineHealthMonitor - Real-time system stability tracking
 * 
 * Tracks error rates, latency, and WAF blocking signals to provide
 * a 'HealthScore' for the Adaptive Throttling Controller.
 */

export class PipelineHealthMonitor {
    constructor(options = {}) {
        this.windowSizeMs = options.windowSizeMs || 60000; // 1 minute window
        this.events = [];
        this.concurrency = options.initialConcurrency || 1;
        this.maxConcurrency = options.maxConcurrency || 10;
        this.minConcurrency = 1;

        // Thresholds
        this.errorThreshold = 0.10; // 10% error rate
        this.blockThreshold = 0.05; // 5% block rate
        this.latencyThresholdMs = 2000; // 2s average latency

        // Perf fix: cooldown + recovery state to avoid log spam and oscillation
        this.lastAdjustment = 0;
        this.adjustmentCooldownMs = options.adjustmentCooldownMs || 5000; // minimum 5s between adjustments
        this.warnedAtMinimum = false;
        this.recoveryThreshold = 0.05; // recover when error rate drops below 5%
    }

    /**
     * Record an execution result
     * @param {object} result - { success, duration, status, isBlock }
     */
    record(result) {
        const now = Date.now();
        this.events.push({
            timestamp: now,
            ...result
        });
        this.prune();
    }

    /**
     * Remove events older than the window size
     */
    prune() {
        const cutoff = Date.now() - this.windowSizeMs;
        this.events = this.events.filter(e => e.timestamp > cutoff);
    }

    /**
     * Calculate current health metrics
     */
    getMetrics() {
        this.prune();
        if (this.events.length === 0) {
            return { errorRate: 0, blockRate: 0, avgLatency: 0, count: 0 };
        }

        let errors = 0;
        let blocks = 0;
        let totalLatency = 0;

        for (const e of this.events) {
            if (!e.success) errors++;
            if (e.isBlock || e.status === 403 || e.status === 429) blocks++;
            totalLatency += (e.duration || 0);
        }

        return {
            errorRate: errors / this.events.length,
            blockRate: blocks / this.events.length,
            avgLatency: totalLatency / this.events.length,
            count: this.events.length
        };
    }

    /**
     * Get recommended concurrency adjustment
     * @returns {string} 'INCREASE', 'DECREASE', 'HOLD', 'EMERGENCY_STOP'
     */
    getRecommendation() {
        const m = this.getMetrics();

        // 1. Critical Blocking / Rate Limiting
        if (m.blockRate > this.blockThreshold) {
            return 'EMERGENCY_BACKOFF';
        }

        // 2. High Error Rate
        if (m.errorRate > this.errorThreshold) {
            return 'DECREASE';
        }

        // 3. High Latency
        if (m.avgLatency > this.latencyThresholdMs) {
            return 'HOLD';
        }

        // 4. Healthy
        return 'INCREASE';
    }

    /**
     * Update internal concurrency target based on recommendation
     * @returns {number} New concurrency limit
     */
    adjustConcurrency() {
        const now = Date.now();
        // Cooldown window: don't adjust too frequently
        if (now - this.lastAdjustment < this.adjustmentCooldownMs) {
            return this.concurrency;
        }

        const action = this.getRecommendation();

        switch (action) {
            case 'EMERGENCY_BACKOFF':
                this.concurrency = 1; // Drop to minimum immediately
                console.log(`⚠️  Pipeline Health: BLOCKING DETECTED! Backing off to concurrency ${this.concurrency}`);
                this.warnedAtMinimum = true; // prevent repeated warnings until recovery
                this.lastAdjustment = now;
                break;
            case 'DECREASE':
                if (this.concurrency <= this.minConcurrency) {
                    if (!this.warnedAtMinimum) {
                        console.warn('⚠️  Pipeline at minimum concurrency - performance may be degraded');
                        this.warnedAtMinimum = true;
                    }
                } else {
                    this.concurrency = Math.max(this.minConcurrency, this.concurrency - 1);
                    console.log(`📉 Pipeline Health: Errors/Latency high. Decreasing concurrency to ${this.concurrency}`);
                    this.warnedAtMinimum = false;
                }
                this.lastAdjustment = now;
                break;
            case 'INCREASE':
                if (this.concurrency < this.maxConcurrency) {
                    // Only increase when truly healthy (below recovery threshold and low latency)
                    const m = this.getMetrics();
                    if (m.errorRate < this.recoveryThreshold && m.avgLatency < this.latencyThresholdMs) {
                        this.concurrency += 1; // Slow ramp up
                        console.log(`📈 Pipeline Health: Improving - increasing concurrency to ${this.concurrency}`);
                        this.warnedAtMinimum = false;
                        this.lastAdjustment = now;
                    }
                }
                break;
            case 'HOLD':
                // Do nothing
                break;
        }

        return this.concurrency;
    }
}
