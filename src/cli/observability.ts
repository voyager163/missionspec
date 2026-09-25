import { lstat, mkdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { TerminalAuthority } from '../adapters/authority/terminal.js';
import { LocalWorkspace } from '../adapters/filesystem/local-workspace.js';
import type { LogPrunePreview } from '../adapters/logging/jsonl.js';
import { validateWindowsStatePath, windowsPrivateEntries } from '../adapters/platform/windows-private-state.js';
import { createUserTelemetryPreferenceStore } from '../adapters/telemetry/preferences.js';
import { requireApproval } from '../application/authority.js';
import { WorkflowError } from '../application/errors.js';
import { createObservabilityLifecycle } from '../composition/observability.js';
import type { ObservedOperation, OperationCompletion } from '../composition/observability.js';
import { parseApprovalReference, parseApprovalRequest } from '../kernel/authority.js';
import { digestEffectScope } from '../kernel/effects.js';
import { parseProjectPath } from '../kernel/identifiers.js';
import { ERROR_CODES } from '../kernel/outcomes.js';
import type { ErrorCode } from '../kernel/outcomes.js';
import { digestContent } from '../kernel/revisions.js';
import { ContractError } from '../kernel/validation.js';
import type { InvocationPolicy, TelemetryPreferenceStore } from '../observability/policy.js';

export type ObservabilityCliValues = Readonly<Record<string, string | boolean | readonly string[] | undefined>>;

const logPath = parseProjectPath('.missionspec/logs/diagnostics.jsonl');
const supported = (): boolean => ['darwin', 'linux', 'win32'].includes(process.platform);
const unavailablePreference = {
  state: 'unavailable', reason: 'io', persistence: 'unchanged', cleanup: 'complete',
} as const;

function policy(values: ObservabilityCliValues): InvocationPolicy {
  return {
    disabled: values['no-telemetry'] !== undefined && values['no-telemetry'] !== false,
    channel: values.json ? 'json' : process.stdin.isTTY && process.stderr.isTTY ? 'interactive' : 'unattended',
  };
}

function preferenceDirectory(): string | undefined {
  if (!supported()) return undefined;
  const explicit = process.env.MISSIONSPEC_CONFIG_HOME;
  const xdg = process.env.XDG_CONFIG_HOME;
  const home = homedir();
  if (process.platform === 'win32') {
    const container = explicit ?? xdg ?? process.env.LOCALAPPDATA ?? home;
    try {
      // Validate the supplied spelling before join can erase dot/alias components.
      validateWindowsStatePath(container);
      const directory = explicit !== undefined ? explicit :
        xdg !== undefined ? path.join(xdg, 'missionspec') :
          process.env.LOCALAPPDATA !== undefined ? path.join(container, 'MissionSpec') :
            path.join(home, 'AppData', 'Local', 'MissionSpec');
      validateWindowsStatePath(path.join(directory, 'telemetry.sqlite'));
      return directory;
    } catch { return undefined; }
  }
  const directory = explicit !== undefined ? explicit : xdg !== undefined ? path.join(xdg, 'missionspec') :
    process.platform === 'darwin' ? path.join(home, 'Library/Application Support/MissionSpec') :
      path.join(home, '.config/missionspec');
  if (!path.isAbsolute(directory) || directory.length > 4000 || /[\u0000-\u001f\u007f]/u.test(directory) ||
      xdg !== undefined && explicit === undefined && !path.isAbsolute(xdg)) return undefined;
  return path.normalize(directory);
}

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

async function preferenceParents(directory: string, create: boolean): Promise<'ready' | 'absent'> {
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      if (!missing(error)) throw error;
      if (!create) return 'absent';
      if (process.platform === 'win32') {
        // Existing profile containers are ancestors, not private leaves. The
        // native helper validates them before atomically securing a new child.
        windowsPrivateEntries([{ path: current, directory: true, writable: true, create: true }]);
      } else {
        try { await mkdir(current, { mode: 0o700 }); } catch (creationError) {
          if (!(typeof creationError === 'object' && creationError !== null &&
              'code' in creationError && creationError.code === 'EEXIST')) throw creationError;
        }
      }
      info = await lstat(current);
    }
    if (!info.isDirectory() || info.isSymbolicLink() || process.platform !== 'win32' && ((info.mode & 0o022) !== 0 ||
        info.uid !== 0 && info.uid !== process.getuid?.() ||
        current === directory && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) {
      throw new TypeError('The preference directory is not privately owned');
    }
  }
  if (directory === path.parse(directory).root) throw new TypeError('A dedicated preference directory is required');
  if (process.platform === 'win32') {
    windowsPrivateEntries([{ path: directory, directory: true, writable: create }]);
  }
  return 'ready';
}

function preferences(): TelemetryPreferenceStore {
  const directory = preferenceDirectory();
  const store = directory === undefined ? undefined :
    createUserTelemetryPreferenceStore(path.join(directory, 'telemetry.sqlite'), { ownership: 'missionspec-telemetry-only' });
  return {
    async read() {
      if (directory === undefined || store === undefined) return unavailablePreference;
      try {
        if (await preferenceParents(directory, false) === 'absent') return { state: 'ready', value: {} };
        return await store.read();
      } catch { return unavailablePreference; }
    },
    async save(patch) {
      if (directory === undefined || store === undefined) return unavailablePreference;
      try {
        await preferenceParents(directory, true);
        return await store.save(patch);
      } catch { return unavailablePreference; }
    },
  };
}

async function logPruneRequest(files: LocalWorkspace, preview: LogPrunePreview) {
  if (preview.path !== path.join(files.root, logPath)) throw new WorkflowError('scope-exceeded', 'Only the dedicated diagnostic log may be pruned.');
  const workspace = await files.identity();
  if (workspace === null) throw new WorkflowError('authority-required', 'Initialize this workspace before requesting diagnostic-log pruning.');
  const file = await files.read(logPath);
  if (file === null || Buffer.byteLength(file.content) !== preview.bytes) {
    throw new WorkflowError('stale-revision', 'The diagnostic log changed after inspection.');
  }
  const effects = [{
    kind: 'file-write' as const, purpose: 'configuration' as const, path: logPath,
    expected: file.digest, proposed: digestContent(''),
  }];
  return parseApprovalRequest({
    contractVersion: 1, state: 'untrusted-request', operation: 'onboard', purpose: 'integration', effects,
    binding: {
      kind: 'project', workspace, effects: digestEffectScope(effects),
      revision: digestContent(JSON.stringify({ action: 'prune-local-diagnostics', preview })),
    },
  });
}

/** Controls are never wrapped as workflow operations or used to enable a production sink. */
export async function runObservabilityCommand(
  positionals: readonly string[], values: ObservabilityCliValues,
): Promise<unknown> {
  const [command, action] = positionals;
  const allowed = command === 'logs' ? ['json', 'no-telemetry', 'preview', 'approval'] : ['json', 'no-telemetry'];
  if (positionals.length !== 2 || Object.keys(values).some((key) => !allowed.includes(key)) ||
      command !== 'logs' && command !== 'telemetry' ||
      command === 'logs' && (action !== 'prune' || values.preview !== undefined && values.approval !== undefined) ||
      command === 'telemetry' && !['status', 'on', 'off', 'preview'].includes(action ?? '') ||
      ['json', 'no-telemetry', 'preview'].some((key) => values[key] !== undefined && typeof values[key] !== 'boolean') ||
      values.approval !== undefined && typeof values.approval !== 'string') {
    throw new WorkflowError('invalid-input', 'Use telemetry status|on|off|preview or logs prune [--preview|--approval <APR-id>].');
  }
  if (command === 'telemetry') {
    const lifecycle = createObservabilityLifecycle({ policy: policy(values), distributedVersion: '0.0.0', preferences: preferences() });
    if (action === 'status') return lifecycle.telemetryStatus();
    if (action === 'preview') {
      const metadata = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
      return lifecycle.previewTelemetry({
        operation: 'draft', access: 'stateful', distributedVersion: metadata.version,
        outcome: 'unknown', host: 'none', os: process.platform === 'darwin' ? 'macos' :
          process.platform === 'linux' ? 'linux' : process.platform === 'win32' ? 'windows' : 'other',
        monotonicDurationMs: null,
      });
    }
    if (!supported()) return { state: 'unavailable', reason: 'unsupported-platform', persistence: 'unchanged', cleanup: 'complete' };
    return lifecycle.setTelemetryPreference(action === 'on' ? 'enabled' : 'disabled');
  }
  if (!supported()) return { state: 'unavailable', reason: 'unsupported-platform', effect: 'unchanged' };
  const files = await LocalWorkspace.open(process.cwd());
  // This read validates private ancestors as well as the fixed target; it never creates a log.
  if (await files.read(logPath) === null) return { state: 'absent' };
  const inspect = createObservabilityLifecycle({
    policy: policy(values), distributedVersion: '0.0.0', localLogPath: path.join(files.root, logPath),
  });
  const preview = await inspect.previewLogPrune();
  if (preview.state !== 'ready' || values.preview) return preview;
  const request = await logPruneRequest(files, preview);
  const rechecked = await inspect.previewLogPrune();
  if (rechecked.state !== 'ready' || rechecked.revision !== preview.revision) {
    throw new WorkflowError('stale-revision', 'The diagnostic log changed during inspection.');
  }
  const authority = await TerminalAuthority.open(files.root);
  let approval;
  if (values.approval !== undefined) {
    approval = parseApprovalReference({ id: values.approval });
  } else {
    const result = await authority.requestConfirmation(request, {
      action: 'prune-local-diagnostics', preview, effect: 'truncate-to-empty',
      excludes: ['runtime-ledger', 'approvals', 'evidence'],
    });
    if (result.status !== 'ok' || result.value.state !== 'issued') {
      throw new WorkflowError('authority-required', 'Diagnostic-log pruning requires genuine local terminal confirmation or its exact persisted approval.');
    }
    approval = result.value.approval.reference;
  }
  // This explicit control resolves native filesystem-backed authority before
  // the composition's one-second optional callback budget, not inside it.
  let issued;
  try {
    const current = await logPruneRequest(files, preview);
    issued = await requireApproval(authority, approval, current, new Date().toISOString());
  } catch (error) {
    return {
      state: 'unavailable',
      reason: error instanceof WorkflowError && error.code !== 'persistence-failed' ?
        'authorization-rejected' : 'authorization-unavailable',
      effect: 'unchanged',
    };
  }
  const verified = issued;
  const lifecycle = createObservabilityLifecycle({
    policy: policy(values), distributedVersion: '0.0.0', localLogPath: path.join(files.root, logPath),
    logPruneAuthorization: {
      async authorize(input) {
        return { state: verified.assurance.channel === 'terminal-confirmation' &&
          verified.reference.id === input.approval.id && Date.parse(verified.expiresAt) > Date.now() &&
          input.preview.path === preview.path && input.preview.bytes === preview.bytes &&
          input.preview.revision === preview.revision ? 'authorized' : 'rejected' };
      },
    },
  });
  return lifecycle.pruneLog(preview, approval);
}

function selectedOperation(positionals: readonly string[], values: ObservabilityCliValues): ObservedOperation | undefined {
  if (values.preview || values.help || values.version) return undefined;
  const command = positionals[0];
  const operation = command === 'capture' ? 'draft' : command === 'patch' ? 'implement' :
    command === 'collect' || command === 'convergence' && values.file !== undefined ? 'verify' :
      command === 'draft' || command === 'draft-all' || command === 'revise' ||
      command === 'principles' || command === 'sync' || command === 'archive' || command === 'implement' ? command : undefined;
  // CLI verify (including --run) currently reads retained evidence; it does not execute checks.
  if (operation === undefined) return undefined;
  return {
    operation, access: 'stateful', scope: 'root', persistence: 'console-only',
    engine: operation === 'implement' ? 'execution' : operation === 'verify' ? 'verification' : 'specification', host: 'none',
  };
}

function field(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
}

function errorCode(value: unknown): ErrorCode | null {
  const code = field(value, 'code');
  return typeof code === 'string' && ERROR_CODES.includes(code as ErrorCode) ? code as ErrorCode : null;
}

function classify(value: unknown, operation: ObservedOperation['operation'], command: string | undefined): OperationCompletion {
  const status = field(value, 'status');
  const code = errorCode(field(value, 'error'));
  if (status === 'outcome-unknown' || code === 'effect-outcome-unknown') return { outcome: 'unknown', errorCode: code };
  if (status === 'blocked' || status === 'failed') return { outcome: status, errorCode: code };
  if (status === 'ok') return classify(field(value, 'value'), operation, command);
  const state = field(value, 'state');
  if (state === 'blocked' || state === 'failed' || state === 'cancelled') return { outcome: state, errorCode: code };
  if (state === 'committed' && (operation !== 'implement' || command === 'patch') && typeof field(value, 'transactionId') === 'string' ||
      state === 'synced' && operation === 'sync') return { outcome: 'completed' };
  if (command === 'collect' && state === 'collected' && typeof field(value, 'runId') === 'string' &&
      Array.isArray(field(value, 'evidence'))) return { outcome: 'completed' };
  const id = field(value, 'id');
  if (command === 'convergence' && typeof id === 'string' &&
      /^convergence-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(id) &&
      field(field(value, 'request'), 'operation') === 'verify' &&
      field(field(value, 'request'), 'purpose') === 'verification' &&
      field(value, 'implementationStarted') === false && field(value, 'testsExecuted') === false) {
    return { outcome: 'completed' };
  }
  if (operation === 'draft-all' && field(value, 'plan') === null) {
    if (field(value, 'stop') === 'review-blocker') return { outcome: 'blocked' };
    if (field(value, 'stop') === 'required-drafts-complete') return { outcome: 'completed' };
  }
  return { outcome: 'unknown', errorCode: code };
}

function classifyError(error: unknown): OperationCompletion {
  if (error instanceof WorkflowError) return {
    outcome: error.code === 'effect-outcome-unknown' ? 'unknown' : 'blocked', errorCode: error.code,
  };
  if (error instanceof ContractError) return { outcome: 'failed', errorCode: 'invalid-input' };
  return { outcome: 'failed', errorCode: errorCode(error) };
}

/** Wrap the functional result itself, not an exit code or output-formatting callback. */
export async function observeCliOperation<T>(
  positionals: readonly string[], values: ObservabilityCliValues, version: string, work: () => Promise<T>,
): Promise<T> {
  const operation = selectedOperation(positionals, values);
  if (operation === undefined) return work();
  const lifecycle = createObservabilityLifecycle({
    policy: policy(values), distributedVersion: version, preferences: preferences(),
  });
  return lifecycle.run(operation, work, (value) => classify(value, operation.operation, positionals[0]), classifyError);
}
