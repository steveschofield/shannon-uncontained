/**
 * Tool Runner - Execute external tools and capture output
 * 
 * Handles:
 * - Tool availability checking
 * - Timeout management
 * - Output capture
 * - Error handling
 */

import { exec } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

/**
 * Tool execution result
 */
export class ToolResult {
    constructor({
        tool,
        success,
        stdout = '',
        stderr = '',
        exitCode = 0,
        duration = 0,
        timedOut = false,
        signal = null,
        killed = false,
        error = null,
    }) {
        this.tool = tool;
        this.success = success;
        this.stdout = stdout;
        this.stderr = stderr;
        this.exitCode = exitCode;
        this.duration = duration;
        this.timedOut = timedOut;
        this.signal = signal;
        this.killed = killed;
        this.error = error;
        this.timestamp = new Date().toISOString();
    }
}

/**
 * Check if a tool is available
 * @param {string} toolName - Tool to check
 * @returns {Promise<boolean>} Whether tool is available
 */
export async function isToolAvailable(toolName) {
    // Prefer invoking a lightweight version/help command to avoid pyenv shim false-positives
    const versionFlags = ['--version', '-version', 'version', '--help'];
    for (const flag of versionFlags) {
        try {
            await execAsync(`${toolName} ${flag}`, { timeout: 5000 });
            return true;
        } catch (_) {
            // keep trying other flags
        }
    }
    // Fallback to PATH check
    try {
        await execAsync(`which ${toolName}`);
        return true;
    } catch {
        return false;
    }
}

/**
 * Run an external tool
 * @param {string} command - Command to run
 * @param {object} options - Execution options
 * @returns {Promise<ToolResult>} Execution result
 */
export async function runTool(command, options = {}) {
    const {
        timeout = 60000,
        cwd = process.cwd(),
        env = {},
        debug = process.env.LSG_DEBUG_TOOLS === '1',
        debugLogDir = process.env.LSG_DEBUG_LOG_DIR || null,
        debugMaxLines = parseInt(process.env.LSG_DEBUG_MAX_LINES || '200', 10),
        context = null,
        meta = null,
    } = options;

    const toolName = command.split(' ')[0];
    const startTime = Date.now();
    let span = null;
    const agentName = context?.agentName || null;
    const stage = context?.stage || null;
    try {
        if (context && typeof context.startSpan === 'function') {
            span = context.startSpan('tool_execution', { tool: toolName, command, cwd });
        }
        if (context && typeof context.logEvent === 'function') {
            context.logEvent({
                type: 'tool_start',
                tool: toolName,
                command,
                cwd,
                timeout_ms: timeout,
                agent: agentName,
                stage,
                meta: meta || undefined,
            });
        }
    } catch {}

    try {
        const { stdout, stderr } = await execAsync(command, {
            cwd,
            env: { ...process.env, ...env },
            timeout,
            maxBuffer: 1024 * 1024 * 20 // 20MB buffer
        });
        const result = new ToolResult({
            tool: toolName,
            success: true,
            stdout,
            stderr,
            duration: Date.now() - startTime,
        });

        if (debug && debugLogDir) {
            await writeDebugLog({
                command,
                cwd,
                timeout,
                meta,
                agentName,
                stage,
                result,
                debugLogDir,
                maxLines: debugMaxLines
            });
        }
        try {
            if (context && typeof context.logEvent === 'function') {
                context.logEvent({
                    type: 'tool_end',
                    tool: toolName,
                    duration: result.duration,
                    success: true,
                    exitCode: result.exitCode,
                    agent: agentName,
                    stage,
                    meta: meta || undefined
                });
            }
            if (span && context) {
                context.endSpan(span, 'success', { duration: result.duration });
            }
        } catch {}
        return result;
    } catch (err) {
        const result = new ToolResult({
            tool: toolName,
            success: false,
            stdout: err.stdout || '',
            stderr: err.stderr || err.message,
            exitCode: err.code || 1,
            duration: Date.now() - startTime,
            timedOut: err.signal === 'SIGTERM',
            signal: err.signal || null,
            killed: !!err.killed,
            error: err.message,
        });
        if (debug && debugLogDir) {
            await writeDebugLog({
                command,
                cwd,
                timeout,
                meta,
                agentName,
                stage,
                result,
                debugLogDir,
                maxLines: debugMaxLines
            });
        }
        try {
            if (context && typeof context.logEvent === 'function') {
                context.logEvent({
                    type: 'tool_end',
                    tool: toolName,
                    duration: result.duration,
                    success: false,
                    exitCode: result.exitCode,
                    timedOut: result.timedOut,
                    signal: result.signal,
                    error: result.error,
                    agent: agentName,
                    stage,
                    meta: meta || undefined
                });
            }
            if (span && context) {
                context.endSpan(span, 'error', { duration: result.duration, error: result.error, exitCode: result.exitCode });
            }
        } catch {}
        return result;
    }
}

/**
 * Run tool with retry logic
 * @param {string} command - Command to run
 * @param {object} options - Execution options
 * @returns {Promise<ToolResult>} Execution result
 */
export async function runToolWithRetry(command, options = {}) {
    const { maxRetries = 2, retryDelay = 1000, ...runOptions } = options;

    let lastResult;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const meta = { ...(runOptions.meta || {}), attempt, maxRetries };
        if (runOptions.context?.logEvent && attempt > 0) {
            runOptions.context.logEvent({ type: 'tool_retry', tool: command.split(' ')[0], attempt, maxRetries });
        }
        lastResult = await runTool(command, { ...runOptions, meta });

        if (lastResult.success) {
            return lastResult;
        }

        // Don't retry on timeout
        if (lastResult.timedOut) {
            return lastResult;
        }

        // Wait before retry
        if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, retryDelay));
        }
    }

    return lastResult;
}

/**
 * Tool timeouts (ms)
 */
export const TOOL_TIMEOUTS = {
    nmap: 120000,
    subfinder: 60000,
    whatweb: 30000,
    gau: 60000,
    katana: 180000,
    httpx: 30000,
    nuclei: 300000,
    commix: 300000,
};

/**
 * Get timeout for a tool
 * @param {string} toolName - Tool name
 * @returns {number} Timeout in ms
 */
export function getToolTimeout(toolName) {
    return TOOL_TIMEOUTS[toolName] || 60000;
}

export default { runTool, runToolWithRetry, isToolAvailable, ToolResult };

async function writeDebugLog({ command, cwd, timeout, meta, agentName, stage, result, debugLogDir, maxLines }) {
    try {
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const base = `${ts}-${sanitizeName(result.tool || 'tool')}.log.json`;
        const file = path.join(debugLogDir, base);

        const splitLines = (s) => String(s || '').split('\n');
        const head = (s) => splitLines(s).slice(0, maxLines).join('\n');
        const tail = (s) => splitLines(s).slice(Math.max(0, splitLines(s).length - maxLines)).join('\n');
        const stdoutLines = splitLines(result.stdout).length;
        const stderrLines = splitLines(result.stderr).length;

        const saveFull = process.env.LSG_DEBUG_SAVE_OUTPUT === '1';
        const shouldSaveStdout = saveFull && result.stdout && stdoutLines > maxLines;
        const shouldSaveStderr = saveFull && result.stderr && stderrLines > maxLines;

        let stdout_file = null;
        let stderr_file = null;
        if (shouldSaveStdout) {
            stdout_file = file.replace(/\.log\.json$/, '.stdout.txt');
            await fsp.writeFile(stdout_file, result.stdout, 'utf-8');
        }
        if (shouldSaveStderr) {
            stderr_file = file.replace(/\.log\.json$/, '.stderr.txt');
            await fsp.writeFile(stderr_file, result.stderr, 'utf-8');
        }

        const payload = {
            timestamp: new Date().toISOString(),
            command,
            cwd,
            timeout_ms: timeout,
            meta: meta || undefined,
            agent: agentName || null,
            stage: stage || null,
            tool: result.tool,
            success: result.success,
            exitCode: result.exitCode,
            duration_ms: result.duration,
            timedOut: result.timedOut,
            signal: result.signal || null,
            killed: result.killed || false,
            error: result.error || null,
            stdout_bytes: (result.stdout || '').length,
            stderr_bytes: (result.stderr || '').length,
            stdout_lines: stdoutLines,
            stderr_lines: stderrLines,
            stdout_head: head(result.stdout),
            stderr_head: head(result.stderr),
            stdout_tail: tail(result.stdout),
            stderr_tail: tail(result.stderr),
            stdout_file,
            stderr_file,
            max_lines: maxLines,
            hint: 'Set LSG_DEBUG_SAVE_OUTPUT=1 to save full stdout/stderr when truncated',
        };
        await fsp.mkdir(debugLogDir, { recursive: true });
        await fsp.writeFile(file, JSON.stringify(payload, null, 2), 'utf-8');
    } catch {
        // Best-effort debug logging; ignore failures
    }
}

function sanitizeName(name) {
    return String(name).replace(/[^a-zA-Z0-9_.-]+/g, '_');
}
