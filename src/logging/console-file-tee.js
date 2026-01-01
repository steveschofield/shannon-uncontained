import fs from 'fs';
import path from 'path';

function formatTimestampForFilename(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  const yyyy = date.getFullYear();
  const mm = pad(date.getMonth() + 1);
  const dd = pad(date.getDate());
  const hh = pad(date.getHours());
  const mi = pad(date.getMinutes());
  const ss = pad(date.getSeconds());
  return `${yyyy}${mm}${dd}-${hh}${mi}${ss}`;
}

function safeWrite(stream, chunk, encoding) {
  try {
    if (!stream.destroyed) stream.write(chunk, encoding);
  } catch {
    // Best-effort only; never break console output
  }
}

export function defaultConsoleLogFilename(date = new Date()) {
  return `console-${formatTimestampForFilename(date)}.log`;
}

export function startConsoleFileTee(logFilePath) {
  if (!logFilePath || typeof logFilePath !== 'string') {
    throw new Error('startConsoleFileTee requires a logFilePath string');
  }

  if (global.__shannonConsoleFileTee?.active) {
    return global.__shannonConsoleFileTee;
  }

  const resolved = path.resolve(logFilePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  try {
    fs.closeSync(fs.openSync(resolved, 'a'));
  } catch {
    // Ignore; createWriteStream will surface failures on write
  }
  const stream = fs.createWriteStream(resolved, { flags: 'a' });

  const originalStdoutWrite = process.stdout.write;
  const originalStderrWrite = process.stderr.write;

  process.stdout.write = function (chunk, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }
    safeWrite(stream, chunk, encoding);
    return originalStdoutWrite.call(process.stdout, chunk, encoding, callback);
  };

  process.stderr.write = function (chunk, encoding, callback) {
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = undefined;
    }
    safeWrite(stream, chunk, encoding);
    return originalStderrWrite.call(process.stderr, chunk, encoding, callback);
  };

  const stop = () => {
    try {
      if (process.stdout.write !== originalStdoutWrite) process.stdout.write = originalStdoutWrite;
    } catch {}
    try {
      if (process.stderr.write !== originalStderrWrite) process.stderr.write = originalStderrWrite;
    } catch {}
    try {
      stream.end();
    } catch {}
    if (global.__shannonConsoleFileTee) global.__shannonConsoleFileTee.active = false;
  };

  global.__shannonConsoleFileTee = {
    active: true,
    logFilePath: resolved,
    stop
  };

  process.once('exit', stop);

  return global.__shannonConsoleFileTee;
}
