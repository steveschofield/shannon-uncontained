/**
 * SchemathesisAgent - API testing via OpenAPI schema
 *
 * Runs schemathesis against generated or discovered OpenAPI specs.
 */

import { BaseAgent } from '../base-agent.js';
import { createEvidenceEvent, EVENT_TYPES } from '../../worldmodel/evidence-graph.js';
import { runToolWithRetry, isToolAvailable, getToolRunOptions } from '../../tools/runners/tool-runner.js';
import { createEpistemicEnvelope } from '../../worldmodel/artifact-manifest.js';

export class SchemathesisAgent extends BaseAgent {
    constructor(options = {}) {
        super('SchemathesisAgent', options);

        this.inputs_schema = {
            type: 'object',
            required: ['target', 'outputDir'],
            properties: {
                target: { type: 'string', description: 'Target URL' },
                outputDir: { type: 'string', description: 'Workspace directory' },
                openapi_path: { type: 'string', description: 'Path to OpenAPI spec (optional)' },
                schemathesis_checks: { type: 'string', description: 'Comma-separated checks' },
                schemathesis_max_examples: { type: 'number', description: 'Max examples per operation' },
                schemathesis_workers: { type: 'number', description: 'Parallel worker count' },
            },
        };

        this.outputs_schema = {
            type: 'object',
            properties: {
                success: { type: 'boolean' },
                report_path: { type: 'string' },
                skipped: { type: 'boolean' },
                reason: { type: 'string' },
            },
        };

        this.requires = {
            evidence_kinds: ['openapi_fragment', EVENT_TYPES.ENDPOINT_DISCOVERED],
            model_nodes: ['endpoint'],
        };

        this.emits = {
            evidence_events: ['api_test_result', EVENT_TYPES.TOOL_ERROR],
            model_updates: [],
            claims: [],
            artifacts: ['schemathesis_report'],
        };

        this.default_budget = {
            max_time_ms: 300000,
            max_network_requests: 1000,
            max_tokens: 0,
            max_tool_invocations: 2,
        };
    }

    async run(ctx, inputs) {
        const { target, outputDir, openapi_path, schemathesis_checks, schemathesis_max_examples, schemathesis_workers } = inputs;
        const { fs, path } = await import('zx');

        if (!await isToolAvailable('schemathesis')) {
            return { success: false, skipped: true, reason: 'schemathesis not installed' };
        }

        const openapiPath = openapi_path || path.join(outputDir, 'openapi.json');
        if (!await fs.pathExists(openapiPath)) {
            return { success: false, skipped: true, reason: 'openapi.json not found' };
        }

        const deliverablesDir = path.join(outputDir, 'deliverables', 'schemathesis');
        await fs.ensureDir(deliverablesDir);
        const reportPath = path.join(deliverablesDir, 'schemathesis-output.txt');

        const cmd = this.buildSchemathesisCommand({
            openapiPath,
            target,
            checks: schemathesis_checks,
            maxExamples: schemathesis_max_examples,
            workers: schemathesis_workers,
        });

        ctx.recordToolInvocation();
        const toolOptions = getToolRunOptions('schemathesis', inputs.toolConfig);
        const result = await runToolWithRetry(cmd, {
            ...toolOptions,
            context: ctx,
        });

        await fs.writeFile(reportPath, [result.stdout, result.stderr].filter(Boolean).join('\n'));

        ctx.emitEvidence(createEvidenceEvent({
            source: this.name,
            event_type: result.success ? 'api_test_result' : EVENT_TYPES.TOOL_ERROR,
            target,
            payload: {
                tool: 'schemathesis',
                success: result.success,
                exit_code: result.exitCode,
                report_path: reportPath,
                error: result.error || null,
            },
        }));

        ctx.manifest.addEntry({
            path: reportPath,
            generated_from: [],
            evidence_refs: [],
            epistemic: createEpistemicEnvelope(
                { b: result.success ? 0.7 : 0.2, d: result.success ? 0.1 : 0.6, u: 0.2, a: 0.5 },
                [],
                [],
                result.success ? [] : ['Schemathesis reported failures']
            ),
        });

        return {
            success: result.success,
            report_path: reportPath,
            skipped: false,
            reason: result.success ? null : result.error,
        };
    }

    buildSchemathesisCommand({ openapiPath, target, checks, maxExamples, workers }) {
        let cmd = `schemathesis run "${openapiPath}" --url "${target}"`;
        if (checks) {
            cmd += ` --checks ${checks}`;
        }
        if (Number.isFinite(maxExamples)) {
            cmd += ` --max-examples ${Math.max(1, maxExamples)}`;
        }
        if (Number.isFinite(workers)) {
            cmd += ` --workers ${Math.max(1, workers)}`;
        }
        return cmd;
    }
}

export default SchemathesisAgent;
