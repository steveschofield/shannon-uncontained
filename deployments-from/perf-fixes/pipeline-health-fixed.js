/**
 * Pipeline Health Monitor Fix
 * 
 * This replaces the broken pipeline health logic that spams logs.
 * 
 * Apply to: src/local-source-generator/v2/orchestrator.js
 * or wherever the pipeline health monitoring code lives.
 */

export class PipelineHealthMonitor {
    constructor(options = {}) {
        this.maxConcurrency = options.maxConcurrency || 5;
        this.minConcurrency = options.minConcurrency || 1;
        this.concurrency = this.maxConcurrency;

        // Track errors and latency
        this.errors = 0;
        this.totalRequests = 0;
        this.latencyWindow = [];
        this.errorWindow = [];

        // ✅ FIX 1: Add cooldown to prevent spam
        this.lastAdjustment = 0;
        this.adjustmentCooldown = 5000; // 5 seconds minimum between adjustments

        // ✅ FIX 2: Track if we've warned about minimum
        this.warnedAtMinimum = false;

        // ✅ FIX 3: Auto-recovery settings
        this.autoRecovery = true;
        this.recoveryThreshold = 0.05; // 5% error rate to recover
    }

    /**
     * Record an agent error
     */
    recordError(agentName, error) {
        this.errors++;
        this.totalRequests++;

        // Keep error window (last 10 seconds)
        this.errorWindow.push({
            timestamp: Date.now(),
            agent: agentName,
            error,
        });

        // Clean old errors
        this.errorWindow = this.errorWindow.filter(
            e => Date.now() - e.timestamp < 10000
        );

        // Check if we need to adjust
        this.checkHealth();
    }

    /**
     * Record successful agent completion
     */
    recordSuccess(agentName, duration) {
        this.totalRequests++;

        // Track latency
        this.latencyWindow.push({
            timestamp: Date.now(),
            agent: agentName,
            duration,
        });

        // Clean old latency data
        this.latencyWindow = this.latencyWindow.filter(
            l => Date.now() - l.timestamp < 10000
        );

        // Check if we can recover
        this.checkHealth();
    }

    /**
     * ✅ FIXED: Check health with cooldown and recovery
     */
    checkHealth() {
        const now = Date.now();

        // ✅ FIX: Cooldown check - don't adjust more than once per 5 seconds
        if (now - this.lastAdjustment < this.adjustmentCooldown) {
            return;
        }

        // Calculate current error rate
        const recentErrors = this.errorWindow.length;
        const recentTotal = this.latencyWindow.length + this.errorWindow.length;
        const errorRate = recentTotal > 0 ? recentErrors / recentTotal : 0;

        // Calculate average latency
        const avgLatency = this.latencyWindow.length > 0
            ? this.latencyWindow.reduce((sum, l) => sum + l.duration, 0) / this.latencyWindow.length
            : 0;

        // ✅ FIX: Decision logic with hysteresis
        if (errorRate > 0.3 || avgLatency > 10000) {
            // High error rate or slow - decrease concurrency
            this.decreaseConcurrency();
        } else if (errorRate < this.recoveryThreshold && avgLatency < 5000) {
            // Low error rate and good latency - increase concurrency
            if (this.autoRecovery && this.concurrency < this.maxConcurrency) {
                this.increaseConcurrency();
            }
        }
    }

    /**
     * ✅ FIXED: Decrease concurrency with spam protection
     */
    decreaseConcurrency() {
        const now = Date.now();

        // ✅ FIX: Already at minimum? Don't spam
        if (this.concurrency <= this.minConcurrency) {
            // Log warning only once
            if (!this.warnedAtMinimum) {
                console.warn('⚠️  Pipeline at minimum concurrency - performance may be degraded');
                console.warn('   Consider fixing agent errors or increasing resources');
                this.warnedAtMinimum = true;
            }
            return;
        }

        this.concurrency = Math.max(this.minConcurrency, this.concurrency - 1);
        this.lastAdjustment = now;
        this.warnedAtMinimum = false; // Reset warning

        console.log(`📉 Pipeline Health: Decreasing concurrency to ${this.concurrency}`);
    }

    /**
     * ✅ NEW: Increase concurrency for auto-recovery
     */
    increaseConcurrency() {
        const now = Date.now();

        if (this.concurrency >= this.maxConcurrency) {
            return;
        }

        this.concurrency = Math.min(this.maxConcurrency, this.concurrency + 1);
        this.lastAdjustment = now;

        console.log(`📈 Pipeline Health: Improving - increasing concurrency to ${this.concurrency}`);
    }

    /**
     * Get current concurrency level
     */
    getConcurrency() {
        return this.concurrency;
    }

    /**
     * Get health statistics
     */
    getStats() {
        const errorRate = this.totalRequests > 0
            ? (this.errors / this.totalRequests * 100).toFixed(2)
            : 0;

        return {
            concurrency: this.concurrency,
            maxConcurrency: this.maxConcurrency,
            totalRequests: this.totalRequests,
            errors: this.errors,
            errorRate: `${errorRate}%`,
            recentErrors: this.errorWindow.length,
            avgLatency: this.latencyWindow.length > 0
                ? Math.round(this.latencyWindow.reduce((sum, l) => sum + l.duration, 0) / this.latencyWindow.length)
                : 0,
        };
    }

    /**
     * Reset statistics
     */
    reset() {
        this.errors = 0;
        this.totalRequests = 0;
        this.errorWindow = [];
        this.latencyWindow = [];
        this.concurrency = this.maxConcurrency;
        this.warnedAtMinimum = false;
        this.lastAdjustment = 0;
    }
}

export default PipelineHealthMonitor;
