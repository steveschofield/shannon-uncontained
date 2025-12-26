/**
 * GlobalRateLimiter - Comprehensive rate limiting system for Shannon
 * 
 * Prevents overwhelming targets with too many requests.
 * Features:
 * - Token bucket algorithm (burst support)
 * - Adaptive throttling (slows down on errors)
 * - Health monitoring (stops if target is dying)
 * - Per-agent limits
 * - Configurable profiles (conservative, normal, aggressive)
 * 
 * Usage:
 * import { GlobalRateLimiter } from './global-rate-limiter.js';
 * 
 * const limiter = GlobalRateLimiter.getInstance();
 * await limiter.throttle('AgentName');
 */

export class GlobalRateLimiter {
    static instance = null;

    constructor(options = {}) {
        // Profile-based presets
        this.profiles = {
            conservative: {
                requestsPerSecond: 5,
                burstSize: 10,
                minDelay: 200,
                errorBackoffMultiplier: 3,
            },
            normal: {
                requestsPerSecond: 10,
                burstSize: 20,
                minDelay: 100,
                errorBackoffMultiplier: 2,
            },
            aggressive: {
                requestsPerSecond: 20,
                burstSize: 40,
                minDelay: 50,
                errorBackoffMultiplier: 1.5,
            },
        };

        const profile = options.profile || 'normal';
        const profileDefaults = this.profiles[profile];

        this.requestsPerSecond = options.requestsPerSecond || profileDefaults.requestsPerSecond;
        this.burstSize = options.burstSize || profileDefaults.burstSize;
        this.minDelay = options.minDelay || profileDefaults.minDelay;
        this.errorBackoffMultiplier = options.errorBackoffMultiplier || profileDefaults.errorBackoffMultiplier;

        // Token bucket for burst support
        this.tokens = this.burstSize;
        this.lastRefill = Date.now();
        this.refillRate = this.requestsPerSecond;

        // Request tracking
        this.requestTimes = [];
        this.lastRequestTime = 0;

        // Health monitoring
        this.errorCount = 0;
        this.consecutiveErrors = 0;
        this.totalRequests = 0;
        this.successfulRequests = 0;
        
        // Adaptive throttling
        this.currentDelay = this.minDelay;
        this.isAdaptiveMode = options.adaptiveMode !== false;

        // Per-agent limits
        this.agentLimits = options.agentLimits || {};
        this.agentStats = {};

        // Circuit breaker
        this.circuitBreakerThreshold = options.circuitBreakerThreshold || 10;
        this.circuitOpen = false;
        this.circuitResetTime = 30000; // 30 seconds

        // Statistics
        this.stats = {
            totalRequests: 0,
            throttledRequests: 0,
            errors: 0,
            avgDelay: this.minDelay,
        };
    }

    /**
     * Singleton pattern
     */
    static getInstance(options = {}) {
        if (!GlobalRateLimiter.instance) {
            GlobalRateLimiter.instance = new GlobalRateLimiter(options);
        }
        return GlobalRateLimiter.instance;
    }

    /**
     * Reset singleton (useful for testing)
     */
    static reset() {
        GlobalRateLimiter.instance = null;
    }

    /**
     * Main throttle method - call before each request
     */
    async throttle(agentName = 'default') {
        // Check circuit breaker
        if (this.circuitOpen) {
            const now = Date.now();
            if (now - this.lastRequestTime < this.circuitResetTime) {
                throw new Error('Circuit breaker open - target appears down. Wait 30 seconds.');
            } else {
                // Try to reset circuit
                this.circuitOpen = false;
                this.consecutiveErrors = 0;
                console.log('Circuit breaker reset - attempting requests again');
            }
        }

        // Refill tokens
        this.refillTokens();

        // Wait for token
        while (this.tokens < 1) {
            await this.delay(100);
            this.refillTokens();
        }

        // Consume token
        this.tokens -= 1;

        // Apply minimum delay
        const timeSinceLastRequest = Date.now() - this.lastRequestTime;
        if (timeSinceLastRequest < this.currentDelay) {
            const waitTime = this.currentDelay - timeSinceLastRequest;
            await this.delay(waitTime);
        }

        // Track request
        this.lastRequestTime = Date.now();
        this.totalRequests++;
        this.stats.totalRequests++;

        // Track per-agent stats
        if (!this.agentStats[agentName]) {
            this.agentStats[agentName] = {
                requests: 0,
                errors: 0,
                lastRequest: 0,
            };
        }
        this.agentStats[agentName].requests++;
        this.agentStats[agentName].lastRequest = Date.now();
    }

    /**
     * Refill token bucket
     */
    refillTokens() {
        const now = Date.now();
        const timePassed = (now - this.lastRefill) / 1000; // seconds
        const tokensToAdd = timePassed * this.refillRate;
        
        this.tokens = Math.min(this.burstSize, this.tokens + tokensToAdd);
        this.lastRefill = now;
    }

    /**
     * Record request success
     */
    recordSuccess(agentName = 'default') {
        this.successfulRequests++;
        this.consecutiveErrors = 0;

        // Adaptive: gradually reduce delay on success
        if (this.isAdaptiveMode && this.currentDelay > this.minDelay) {
            this.currentDelay = Math.max(
                this.minDelay,
                this.currentDelay * 0.95
            );
        }

        if (this.agentStats[agentName]) {
            // Success recorded
        }
    }

    /**
     * Record request error
     */
    recordError(agentName = 'default', errorType = 'unknown') {
        this.errorCount++;
        this.consecutiveErrors++;
        this.stats.errors++;

        if (this.agentStats[agentName]) {
            this.agentStats[agentName].errors++;
        }

        // Adaptive: increase delay on error
        if (this.isAdaptiveMode) {
            this.currentDelay = Math.min(
                5000, // Max 5 second delay
                this.currentDelay * this.errorBackoffMultiplier
            );
        }

        // Circuit breaker
        if (this.consecutiveErrors >= this.circuitBreakerThreshold) {
            this.circuitOpen = true;
            console.error(`Circuit breaker opened after ${this.consecutiveErrors} consecutive errors`);
        }

        // Log warning
        if (this.consecutiveErrors >= 5) {
            console.warn(`Warning: ${this.consecutiveErrors} consecutive errors. Current delay: ${this.currentDelay}ms`);
        }
    }

    /**
     * Get current rate limit status
     */
    getStatus() {
        const errorRate = this.totalRequests > 0 
            ? (this.errorCount / this.totalRequests * 100).toFixed(2)
            : 0;

        return {
            requestsPerSecond: this.requestsPerSecond,
            currentDelay: this.currentDelay,
            tokens: this.tokens.toFixed(2),
            totalRequests: this.totalRequests,
            successfulRequests: this.successfulRequests,
            errorCount: this.errorCount,
            consecutiveErrors: this.consecutiveErrors,
            errorRate: `${errorRate}%`,
            circuitOpen: this.circuitOpen,
            isThrottling: this.currentDelay > this.minDelay,
        };
    }

    /**
     * Get per-agent statistics
     */
    getAgentStats() {
        return this.agentStats;
    }

    /**
     * Update configuration on the fly
     */
    updateConfig(options) {
        if (options.requestsPerSecond) {
            this.requestsPerSecond = options.requestsPerSecond;
            this.refillRate = options.requestsPerSecond;
        }
        if (options.minDelay) {
            this.minDelay = options.minDelay;
        }
        if (options.profile) {
            const profile = this.profiles[options.profile];
            if (profile) {
                this.requestsPerSecond = profile.requestsPerSecond;
                this.minDelay = profile.minDelay;
                this.errorBackoffMultiplier = profile.errorBackoffMultiplier;
            }
        }
    }

    /**
     * Set profile (conservative, normal, aggressive)
     */
    setProfile(profileName) {
        this.updateConfig({ profile: profileName });
        console.log(`Rate limiter profile changed to: ${profileName}`);
    }

    /**
     * Reset statistics
     */
    resetStats() {
        this.errorCount = 0;
        this.consecutiveErrors = 0;
        this.totalRequests = 0;
        this.successfulRequests = 0;
        this.currentDelay = this.minDelay;
        this.circuitOpen = false;
        this.stats = {
            totalRequests: 0,
            throttledRequests: 0,
            errors: 0,
            avgDelay: this.minDelay,
        };
        this.agentStats = {};
    }

    /**
     * Delay helper
     */
    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * RequestWrapper - Wraps fetch with automatic rate limiting and error handling
 */
export class RequestWrapper {
    constructor(limiter = null, agentName = 'default') {
        this.limiter = limiter || GlobalRateLimiter.getInstance();
        this.agentName = agentName;
    }

    /**
     * Fetch with automatic rate limiting and retry
     */
    async fetch(url, options = {}, retries = 3) {
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                // Throttle before request
                await this.limiter.throttle(this.agentName);

                // Make request
                const response = await fetch(url, {
                    ...options,
                    timeout: options.timeout || 10000,
                });

                // Record success
                this.limiter.recordSuccess(this.agentName);

                return response;

            } catch (error) {
                // Determine error type
                const errorType = this.classifyError(error);

                // Record error
                this.limiter.recordError(this.agentName, errorType);

                // If last attempt, throw
                if (attempt === retries) {
                    throw error;
                }

                // Wait before retry (exponential backoff)
                const backoffDelay = Math.min(1000 * Math.pow(2, attempt), 5000);
                await this.limiter.delay(backoffDelay);

                console.log(`Retry ${attempt + 1}/${retries} for ${url}`);
            }
        }
    }

    /**
     * Classify error type
     */
    classifyError(error) {
        const message = error.message.toLowerCase();
        
        if (message.includes('timeout')) return 'timeout';
        if (message.includes('econnrefused')) return 'connection_refused';
        if (message.includes('econnreset')) return 'connection_reset';
        if (message.includes('etimedout')) return 'timeout';
        if (message.includes('network')) return 'network';
        
        return 'unknown';
    }
}

/**
 * Helper function to wrap agent methods with rate limiting
 */
export function withRateLimit(agentName) {
    const limiter = GlobalRateLimiter.getInstance();
    const wrapper = new RequestWrapper(limiter, agentName);

    return {
        throttle: () => limiter.throttle(agentName),
        fetch: (url, options, retries) => wrapper.fetch(url, options, retries),
        recordSuccess: () => limiter.recordSuccess(agentName),
        recordError: (errorType) => limiter.recordError(agentName, errorType),
    };
}

export default GlobalRateLimiter;
