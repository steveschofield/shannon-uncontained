/**
 * WAFDetector Fix - Patch for "ctx is not defined" error
 * 
 * Apply this patch to: src/local-source-generator/v2/agents/recon/waf-detector.js
 * 
 * The issue is that WAFDetector is using 'ctx' outside the run() method.
 * This patch shows the correct pattern.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class WAFDetector extends BaseAgent {
    constructor(options = {}) {
        super('WAFDetector', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                waf_detected: { type: 'boolean' },
                waf_name: { type: 'string' },
                waf_manufacturer: { type: 'string' },
            },
        };

        this.requires = {
            evidence_kinds: [],
            model_nodes: []
        };

        this.emits = {
            evidence_events: ['waf_detected', 'waf_identified'],
            model_updates: [],
            claims: ['has_waf'],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 30000,
            max_network_requests: 10,
            max_tokens: 0,
            max_tool_invocations: 1,
        };

        // ✅ CORRECT: Initialize properties here, not methods that use ctx
        this.wafSignatures = [
            'cloudflare',
            'akamai',
            'imperva',
            'f5',
            'aws waf',
            'azure waf',
        ];
    }

    // ✅ CORRECT: Main entry point with ctx parameter
    async run(ctx, inputs) {
        const { target } = inputs;

        const results = {
            waf_detected: false,
            waf_name: null,
            waf_manufacturer: null,
        };

        this.setStatus('Detecting WAF...');

        try {
            // Check if wafw00f is installed
            if (!await this.checkWafw00fInstalled()) {
                console.warn('⚠️  wafw00f not installed - skipping WAF detection');
                return results;
            }

            // Run WAF detection
            const wafInfo = await this.detectWAF(ctx, target);

            if (wafInfo.detected) {
                results.waf_detected = true;
                results.waf_name = wafInfo.name;
                results.waf_manufacturer = wafInfo.manufacturer;

                // ✅ CORRECT: Use ctx inside run() or methods called from run()
                ctx.emitEvidence(createEvidenceEvent({
                    source: this.name,
                    event_type: 'waf_detected',
                    target,
                    payload: {
                        waf_name: wafInfo.name,
                        waf_manufacturer: wafInfo.manufacturer,
                    },
                }));

                ctx.emitClaim({
                    claim_type: 'has_waf',
                    subject: target,
                    predicate: { waf: wafInfo.name },
                    base_rate: 0.5,
                });

                this.setStatus(`WAF detected: ${wafInfo.name}`);
            } else {
                this.setStatus('No WAF detected');
            }

        } catch (error) {
            console.error('Error detecting WAF:', error.message);
            // Don't crash - return empty results
        }

        return results;
    }

    /**
     * Check if wafw00f is installed
     */
    async checkWafw00fInstalled() {
        try {
            await execAsync('which wafw00f');
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Detect WAF using wafw00f
     * ✅ CORRECT: Accept ctx as parameter
     */
    async detectWAF(ctx, target) {
        try {
            const { stdout } = await execAsync(`wafw00f ${target} -o /dev/null 2>&1`);

            // Parse wafw00f output
            const detected = !stdout.includes('No WAF detected');
            let name = null;
            let manufacturer = null;

            if (detected) {
                // Extract WAF name from output
                for (const signature of this.wafSignatures) {
                    if (stdout.toLowerCase().includes(signature)) {
                        name = signature;
                        break;
                    }
                }
            }

            return {
                detected,
                name,
                manufacturer,
            };

        } catch (error) {
            return {
                detected: false,
                name: null,
                manufacturer: null,
            };
        }
    }
}

export default WAFDetector;
