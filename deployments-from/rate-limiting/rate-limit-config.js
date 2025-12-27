/**
 * Rate Limit Configuration Profiles
 * 
 * Pre-configured profiles for different target types.
 * Use these to avoid crashing targets or getting blocked.
 */

export const RATE_LIMIT_PROFILES = {
    /**
     * STEALTH - For targets with strict rate limiting or WAFs
     * Use for: Production sites, bug bounties with strict rules
     */
    stealth: {
        global: {
            requestsPerSecond: 3,
            burstSize: 5,
            minDelay: 300,
            errorBackoffMultiplier: 4,
        },
        agents: {
            EnhancedNucleiScanAgent: {
                nucleiArgs: '-rate-limit 20 -bulk-size 3 -c 3',
                maxTemplates: 1000,
            },
            ParameterDiscoveryAgent: {
                maxEndpoints: 3,
                maxParameters: 5,
                requestDelay: 400,
            },
            NoSQLInjectionAgent: {
                maxInjectionPoints: 5,
                maxPayloads: 3,
                requestDelay: 400,
            },
            BusinessLogicFuzzer: {
                maxDiscountTests: 3,
                maxPriceTests: 3,
                requestDelay: 500,
            },
        },
    },

    /**
     * CONSERVATIVE - For fragile targets (local dev, Juice Shop)
     * Use for: Local docker containers, development servers
     */
    conservative: {
        global: {
            requestsPerSecond: 5,
            burstSize: 10,
            minDelay: 200,
            errorBackoffMultiplier: 3,
        },
        agents: {
            EnhancedNucleiScanAgent: {
                nucleiArgs: '-rate-limit 30 -bulk-size 5 -c 5',
                maxTemplates: 2000,
            },
            ParameterDiscoveryAgent: {
                maxEndpoints: 5,
                maxParameters: 10,
                requestDelay: 200,
            },
            NoSQLInjectionAgent: {
                maxInjectionPoints: 10,
                maxPayloads: 5,
                requestDelay: 200,
            },
            DOMXSSAgent: {
                maxJsFiles: 5,
                maxPayloads: 5,
            },
            BusinessLogicFuzzer: {
                maxDiscountTests: 5,
                maxPriceTests: 5,
                requestDelay: 300,
            },
            CSRFDetector: {
                maxEndpoints: 10,
            },
            SSRFDetector: {
                maxParameters: 5,
                requestDelay: 300,
            },
        },
    },

    /**
     * NORMAL - For typical production websites
     * Use for: Most production sites, staging environments
     */
    normal: {
        global: {
            requestsPerSecond: 10,
            burstSize: 20,
            minDelay: 100,
            errorBackoffMultiplier: 2,
        },
        agents: {
            EnhancedNucleiScanAgent: {
                nucleiArgs: '-rate-limit 50 -bulk-size 10 -c 10',
                maxTemplates: 3000,
            },
            ParameterDiscoveryAgent: {
                maxEndpoints: 10,
                maxParameters: 20,
                requestDelay: 100,
            },
            NoSQLInjectionAgent: {
                maxInjectionPoints: 15,
                maxPayloads: 7,
                requestDelay: 100,
            },
            DOMXSSAgent: {
                maxJsFiles: 10,
                maxPayloads: 10,
            },
            BusinessLogicFuzzer: {
                maxDiscountTests: 7,
                maxPriceTests: 6,
                requestDelay: 150,
            },
            CSRFDetector: {
                maxEndpoints: 20,
            },
            SSRFDetector: {
                maxParameters: 10,
                requestDelay: 150,
            },
            GraphQLTester: {
                maxDepthTest: 30,
                maxBatchSize: 50,
            },
        },
    },

    /**
     * AGGRESSIVE - For resilient targets with good infrastructure
     * Use for: Large cloud deployments, CDN-backed sites
     */
    aggressive: {
        global: {
            requestsPerSecond: 20,
            burstSize: 40,
            minDelay: 50,
            errorBackoffMultiplier: 1.5,
        },
        agents: {
            EnhancedNucleiScanAgent: {
                nucleiArgs: '-rate-limit 100 -bulk-size 20 -c 20',
                maxTemplates: 5000,
            },
            ParameterDiscoveryAgent: {
                maxEndpoints: 20,
                maxParameters: 30,
                requestDelay: 50,
            },
            NoSQLInjectionAgent: {
                maxInjectionPoints: 20,
                maxPayloads: 9,
                requestDelay: 50,
            },
            DOMXSSAgent: {
                maxJsFiles: 20,
                maxPayloads: 15,
            },
            BusinessLogicFuzzer: {
                maxDiscountTests: 10,
                maxPriceTests: 8,
                requestDelay: 100,
            },
            CSRFDetector: {
                maxEndpoints: 30,
            },
            SSRFDetector: {
                maxParameters: 15,
                requestDelay: 100,
            },
            GraphQLTester: {
                maxDepthTest: 50,
                maxBatchSize: 100,
            },
        },
    },

    /**
     * CUSTOM - Template for custom configurations
     */
    custom: {
        global: {
            requestsPerSecond: 10,
            burstSize: 20,
            minDelay: 100,
            errorBackoffMultiplier: 2,
        },
        agents: {},
    },
};

/**
 * Target-specific presets
 */
export const TARGET_PRESETS = {
    'juice-shop': 'conservative',
    'localhost': 'conservative',
    '127.0.0.1': 'conservative',
    'docker': 'conservative',
    'dev': 'conservative',
    'staging': 'normal',
    'production': 'normal',
    'heroku': 'normal',
    'vercel': 'aggressive',
    'netlify': 'aggressive',
    'cloudflare': 'aggressive',
};

/**
 * Get recommended profile for target
 */
export function getRecommendedProfile(target) {
    const lowerTarget = target.toLowerCase();

    // Check for exact matches
    for (const [keyword, profile] of Object.entries(TARGET_PRESETS)) {
        if (lowerTarget.includes(keyword)) {
            return profile;
        }
    }

    // Default to normal
    return 'normal';
}

/**
 * Load profile configuration
 */
export function loadProfile(profileName) {
    const profile = RATE_LIMIT_PROFILES[profileName];
    
    if (!profile) {
        console.warn(`Unknown profile: ${profileName}, using 'normal'`);
        return RATE_LIMIT_PROFILES.normal;
    }

    return profile;
}

/**
 * Merge custom configuration with profile
 */
export function mergeConfig(profileName, customConfig = {}) {
    const profile = loadProfile(profileName);
    
    return {
        global: {
            ...profile.global,
            ...(customConfig.global || {}),
        },
        agents: {
            ...profile.agents,
            ...(customConfig.agents || {}),
        },
    };
}

export default {
    RATE_LIMIT_PROFILES,
    TARGET_PRESETS,
    getRecommendedProfile,
    loadProfile,
    mergeConfig,
};
