/**
 * EnhancedNucleiScanAgent - Comprehensive Nuclei integration
 * 
 * Runs Nuclei with comprehensive template sets for maximum coverage.
 * Covers CVEs, exposures, misconfigurations, default credentials, and more.
 * 
 * Nuclei advantages over ZAP/Burp:
 * - 5,000+ community templates (updated daily)
 * - Fast parallel execution (5-10 min vs 30-60 min)
 * - CLI-first design (perfect for automation)
 * - YAML templates (easy to customize)
 * - Low false positive rate
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { CLAIM_TYPES } from '../../epistemics/ledger.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';

const execAsync = promisify(exec);

export class EnhancedNucleiScanAgent extends BaseAgent {
    constructor(options = {}) {
        super('EnhancedNucleiScanAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                depth: { 
                    type: 'string', 
                    enum: ['fast', 'medium', 'deep'],
                    default: 'medium',
                    description: 'Scan depth (fast=critical only, medium=high+critical, deep=all)'
                },
                customTemplates: {
                    type: 'array',
                    description: 'Additional custom template paths',
                    items: { type: 'string' }
                },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' } },
                exposures: { type: 'array', items: { type: 'object' } },
                misconfigurations: { type: 'array', items: { type: 'object' } },
                total_findings: { type: 'number' },
                severity_breakdown: { type: 'object' },
            },
        };

        this.requires = {
            evidence_kinds: [EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: []
        };

        this.emits = {
            evidence_events: [
                'nuclei_vulnerability_found',
                'nuclei_exposure_found',
                'nuclei_misconfiguration_found',
                EVENT_TYPES.VULNERABILITY_FOUND,
            ],
            model_updates: [],
            claims: [
                'cve_present',
                'exposed_service',
                'misconfigured_server',
                'default_credentials',
            ],
            artifacts: [],
        };

        this.default_budget = {
            max_time_ms: 600000, // 10 minutes
            max_network_requests: 5000,
            max_tokens: 0,
            max_tool_invocations: 1,
        };

        // Template sets by scan depth
        this.templateSets = {
            fast: [
                'cves/2024/',
                'cves/2025/',
                'exposures/configs/',
                'exposures/apis/',
                'default-logins/',
            ],
            medium: [
                'cves/2024/',
                'cves/2025/',
                'cves/2023/',
                'exposures/',
                'misconfigurations/',
                'default-logins/',
                'technologies/',
            ],
            deep: [
                'cves/',
                'exposures/',
                'misconfigurations/',
                'default-logins/',
                'technologies/',
                'vulnerabilities/',
                'fuzzing/',
                'headless/',
            ],
        };

        // Severity mapping
        this.severityMap = {
            critical: 5,
            high: 4,
            medium: 3,
            low: 2,
            info: 1,
        };
    }

    async run(ctx, inputs) {
        const { target, depth = 'medium', customTemplates = [] } = inputs;

        const results = {
            vulnerabilities: [],
            exposures: [],
            misconfigurations: [],
            total_findings: 0,
            severity_breakdown: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
        };

        this.setStatus('Running Nuclei scan...');

        // Check if nuclei is installed
        if (!await this.checkNucleiInstalled()) {
            this.setStatus('Nuclei not installed - skipping');
            return results;
        }

        // Run nuclei with appropriate templates
        const findings = await this.runNucleiScan(ctx, target, depth, customTemplates);

        // Process and categorize findings
        for (const finding of findings) {
            this.processFinding(ctx, finding, results, target);
        }

        results.total_findings = findings.length;

        this.setStatus(`Found ${results.total_findings} issues via Nuclei`);

        return results;
    }

    /**
     * Check if nuclei is installed
     */
    async checkNucleiInstalled() {
        try {
            await execAsync('nuclei -version');
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Run nuclei scan with specified templates
     */
    async runNucleiScan(ctx, target, depth, customTemplates) {
        const templates = this.templateSets[depth] || this.templateSets.medium;
        const tempFile = path.join(os.tmpdir(), `nuclei-${Date.now()}.jsonl`);

        try {
            // Build nuclei command
            const templateArgs = templates.map(t => `-t ${t}`).join(' ');
            const customArgs = customTemplates.map(t => `-t ${t}`).join(' ');
            
            const command = [
                'nuclei',
                `-u ${target}`,
                templateArgs,
                customArgs,
                '-jsonl',
                `-o ${tempFile}`,
                '-silent',
                '-stats',
                '-rate-limit 150', // Don't overwhelm target
                '-bulk-size 25',   // Parallel template execution
                '-c 25',           // Concurrent requests
            ].join(' ');

            this.setStatus(`Executing: ${command.substring(0, 100)}...`);

            // Run nuclei (timeout after 10 minutes)
            await execAsync(command, { 
                timeout: 600000,
                maxBuffer: 10 * 1024 * 1024, // 10MB buffer
            });

            // Read results
            const output = await fs.readFile(tempFile, 'utf-8');
            const findings = output
                .split('\n')
                .filter(line => line.trim())
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch (e) {
                        return null;
                    }
                })
                .filter(Boolean);

            // Cleanup
            await fs.unlink(tempFile).catch(() => {});

            return findings;

        } catch (error) {
            if (error.killed) {
                this.setStatus('Nuclei scan timed out');
            } else {
                this.setStatus(`Nuclei error: ${error.message}`);
            }
            
            // Try to read partial results
            try {
                const output = await fs.readFile(tempFile, 'utf-8');
                await fs.unlink(tempFile).catch(() => {});
                
                return output
                    .split('\n')
                    .filter(line => line.trim())
                    .map(line => {
                        try {
                            return JSON.parse(line);
                        } catch (e) {
                            return null;
                        }
                    })
                    .filter(Boolean);
            } catch (e) {
                return [];
            }
        }
    }

    /**
     * Process individual finding
     */
    processFinding(ctx, finding, results, target) {
        const {
            info = {},
            matched_at,
            matcher_name,
            type,
            host,
        } = finding;

        const {
            name,
            severity = 'info',
            description,
            reference = [],
            classification = {},
            tags = [],
        } = info;

        // Update severity breakdown
        const severityLower = severity.toLowerCase();
        if (results.severity_breakdown[severityLower] !== undefined) {
            results.severity_breakdown[severityLower]++;
        }

        // Categorize finding
        const category = this.categorizeFinding(finding);

        const processedFinding = {
            name,
            severity,
            description,
            matched_at,
            matcher_name,
            type,
            category,
            tags,
            cve: classification['cve-id'] || null,
            cwe: classification['cwe-id'] || null,
            references: Array.isArray(reference) ? reference : [reference].filter(Boolean),
        };

        // Add to appropriate category
        if (category === 'vulnerability') {
            results.vulnerabilities.push(processedFinding);
        } else if (category === 'exposure') {
            results.exposures.push(processedFinding);
        } else if (category === 'misconfiguration') {
            results.misconfigurations.push(processedFinding);
        }

        // Emit evidence for high/critical findings
        if (this.severityMap[severityLower] >= 3) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: `nuclei_${category}_found`,
                target,
                payload: {
                    name,
                    severity,
                    description,
                    matched_at,
                    cve: processedFinding.cve,
                    cwe: processedFinding.cwe,
                },
            }));

            // Emit claims for critical issues
            if (severityLower === 'critical') {
                if (processedFinding.cve) {
                    ctx.emitClaim({
                        claim_type: 'cve_present',
                        subject: matched_at || target,
                        predicate: { 
                            cve: processedFinding.cve,
                            severity: 'critical',
                        },
                        base_rate: 0.5,
                    });
                }

                if (category === 'exposure') {
                    ctx.emitClaim({
                        claim_type: 'exposed_service',
                        subject: matched_at || target,
                        predicate: { 
                            type: name,
                            severity: 'critical',
                        },
                        base_rate: 0.5,
                    });
                }
            }
        }

        // Emit vulnerability event for critical/high
        if (this.severityMap[severityLower] >= 4) {
            ctx.emitEvidence(createEvidenceEvent({
                source: this.name,
                event_type: EVENT_TYPES.VULNERABILITY_FOUND,
                target,
                payload: {
                    vulnerability_type: category,
                    severity,
                    name,
                    description,
                    cve: processedFinding.cve,
                    proof: matched_at,
                },
            }));
        }
    }

    /**
     * Categorize finding based on tags and template path
     */
    categorizeFinding(finding) {
        const tags = finding.info?.tags || [];
        const templateId = finding.template_id || finding.info?.['template-id'] || '';

        // Check template path
        if (templateId.includes('cves/')) {
            return 'vulnerability';
        }
        if (templateId.includes('exposures/')) {
            return 'exposure';
        }
        if (templateId.includes('misconfigurations/')) {
            return 'misconfiguration';
        }
        if (templateId.includes('default-login')) {
            return 'exposure';
        }

        // Check tags
        const tagStr = tags.join(',').toLowerCase();
        
        if (tagStr.includes('cve') || tagStr.includes('exploit')) {
            return 'vulnerability';
        }
        if (tagStr.includes('exposure') || tagStr.includes('disclosure')) {
            return 'exposure';
        }
        if (tagStr.includes('config') || tagStr.includes('misconfiguration')) {
            return 'misconfiguration';
        }

        // Default
        return 'misconfiguration';
    }
}

export default EnhancedNucleiScanAgent;
