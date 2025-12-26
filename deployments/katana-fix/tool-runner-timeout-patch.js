/**
 * Tool Runner - Alternative Fix
 * 
 * PATCH: Increased Katana timeout from 180s → 240s (4 minutes)
 * This gives Katana more time to complete depth-3 crawls on large SPAs
 * 
 * Apply this ONLY IF you prefer keeping depth-3 default
 * Otherwise, use the crawler-agent-patched.js fix (depth 2) instead
 */

/**
 * Tool timeouts (ms)
 */
export const TOOL_TIMEOUTS = {
    nmap: 120000,       // 2 minutes (unchanged)
    subfinder: 60000,   // 1 minute (unchanged)
    whatweb: 30000,     // 30 seconds (unchanged)
    gau: 60000,         // 1 minute (unchanged)
    katana: 240000,     // ✅ CHANGED: 180000 → 240000 (4 minutes, was 3 minutes)
    httpx: 30000,       // 30 seconds (unchanged)
    nuclei: 300000,     // 5 minutes (unchanged)
    commix: 300000,     // 5 minutes (unchanged)
};

/**
 * Get timeout for a tool
 * @param {string} toolName - Tool name
 * @returns {number} Timeout in ms
 */
export function getToolTimeout(toolName) {
    return TOOL_TIMEOUTS[toolName] || 60000;
}

// ... rest of tool-runner.js code remains unchanged
