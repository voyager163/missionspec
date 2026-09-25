#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import {
  ENGINE_IDS, OPERATION_IDS, OPERATIONS, loadPackagedSkillCatalog, renderSkill,
} from '../api/index.js';
import { CONTRACT_VERSION } from '../kernel/protocol.js';
import type { ErrorCode, Outcome } from '../kernel/outcomes.js';
import { ContractError } from '../kernel/validation.js';
import { parseMarkdownSet } from '../engines/specification/contracts.js';
import { ArtifactReadError, readMarkdownSources } from '../adapters/filesystem/artifacts.js';
import { localCommands, runLocalCommand } from './local.js';
import { WorkflowError } from '../application/errors.js';
import { runSkillInstallation } from './installation.js';
import { serveMissionSpecStdio } from '../mcp/server.js';
import { reviewCommands, runReviewCommand } from './reviews.js';
import { observeCliOperation, runObservabilityCommand } from './observability.js';
import { runStateCommand } from './state.js';

const help = `MissionSpec local development CLI

Commands (mutations require local confirmation):
  missionspec capabilities [--json]
  missionspec skills list [--json]
  missionspec skills render --host <copilot|codex|claude> --operation <id> [--json]
  missionspec skills inspect [--host <host>]
  missionspec skills install|update|remove --host <host> [--preview]
    (or repeat --hosts <host> for an explicit multi-host selection)
  missionspec validate <artifact.md>... [--json]
  missionspec project status | change list [--json]
  missionspec state status [--json]
  missionspec state backup [--preview]
  missionspec state stage|restore --file <private-backup.json> [--preview]
  missionspec state select <absolute-path/.missionspec/state> [--preview]
  missionspec state activate <sha256-stage-id> [--preview]
  missionspec state recover <sha256-stage-id> <transaction-id> [--preview]
  missionspec state migrate [--preview]
  missionspec state migrate <absolute-path/.missionspec/state> --file <private-backup.json> [--preview]
  missionspec init [--preview] [--profile standard|compact]
  missionspec change new <slug> --spec <name> [--source <path>] [--verification-plan] [--preview]
  missionspec status|instructions|analyze|clarify|verify <slug> [--json]
  missionspec draft|capture|revise <slug> --artifact <node> [--preview]
  missionspec draft-all <slug> [--preview]
  missionspec discover|clarify <slug> --file <input> [--preview]
  missionspec principles --file <markdown> [--preview]
  missionspec applicability <slug> --reason <text>|--required [--preview]
  missionspec patch <slug> --task <TSK-id> --file <inert-proposal.json> [--preview]
    (dependent tasks require --run <RUN-id> and --evidence <EVD-id>)
  missionspec check register <slug> --file <registration.json> [--preview]
  missionspec collect <slug> --registration <check-id> [--run <RUN-id>] [--preview]
  missionspec verify <slug> --run <RUN-id> --evidence <EVD-id>
  missionspec run status <RUN-id> [--json]
  missionspec accept|sync|archive <slug> --run <RUN-id> --evidence <EVD-id> [--preview]
  missionspec sync|archive <slug> --acceptance <APR-id> [--preview]
  missionspec archive <slug> --outcome rejected|cancelled|incomplete [--preview]
  missionspec recover [transaction-id] [--preview]
  missionspec approval show|revoke <APR-id>
  missionspec onboard [--json]
  missionspec adopt --file <adoption.json> [--preview]
  missionspec context status [--json]
  missionspec convergence <slug> [--file <review.json> --preview]
  missionspec lessons history <lesson-id> [--json]
  missionspec lessons select <slug> --file <selection.json>
  missionspec lessons capture|evaluate|transition <slug> --file <review.json> [--preview]
  missionspec evidence prune --evidence <EVD-id> [--preview]
  missionspec evidence pending | status <sha256-id>
  missionspec evidence recover <sha256-id> [--preview]
  missionspec telemetry status|on|off|preview [--json]
  missionspec logs prune [--preview|--approval <APR-id>]
  missionspec mcp [--no-telemetry]
  missionspec --version

Read-only commands never send telemetry. --no-telemetry is also accepted.
--preview never writes. Mutations display exact changes on the local terminal
and require a fresh challenge response (or --approval for an exact current
persisted grant). Piped/JSON answers, --yes, and --auto cannot grant authority.
Guided archive reviews acceptance, promotion and closure separately.
Registered local checks have no filesystem/network sandbox; mandatory hard
confinement is refused. Native coding-host execution remains unqualified.
MCP uses the current working directory as its fixed configured root. Its stdout
is reserved for protocol messages; --json, --help and --version do not apply.
`;

const cliOptions = {
  json: { type: 'boolean' }, help: { type: 'boolean' }, version: { type: 'boolean' },
  'no-telemetry': { type: 'boolean' }, host: { type: 'string' }, operation: { type: 'string' },
  preview: { type: 'boolean' }, profile: { type: 'string' }, artifact: { type: 'string' },
  spec: { type: 'string', multiple: true }, source: { type: 'string', multiple: true },
  run: { type: 'string' }, evidence: { type: 'string', multiple: true },
  acceptance: { type: 'string' }, outcome: { type: 'string' },
  approval: { type: 'string' }, reason: { type: 'string' }, required: { type: 'boolean' },
  file: { type: 'string' }, registration: { type: 'string', multiple: true }, auto: { type: 'boolean' },
  task: { type: 'string' },
  hosts: { type: 'string', multiple: true },
  'verification-plan': { type: 'boolean' },
} as const;

interface CliIO {
  stdout(value: string): void;
  stderr(value: string): void;
}

function failure(code: ErrorCode, message: string, blocked = false): Outcome<never> {
  return {
    status: blocked ? 'blocked' : 'failed',
    error: { code, message, retry: 'never', fields: [] },
  };
}

function emitFailure(io: CliIO, json: boolean, outcome: Outcome<never>): number {
  if (json) io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, ...outcome })}\n`);
  else if (outcome.status !== 'ok') io.stderr(`${outcome.error.code}: ${outcome.error.message}\n`);
  return outcome.status === 'blocked' ? 2 : 1;
}

async function distributedVersion(): Promise<string> {
  const content = await readFile(new URL('../../package.json', import.meta.url), 'utf8');
  const metadata: unknown = JSON.parse(content);
  if (typeof metadata !== 'object' || metadata === null || !('version' in metadata) ||
      typeof metadata.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(metadata.version)) {
    throw new ContractError('package.version', 'invalid distribution metadata');
  }
  return metadata.version;
}

export async function runCli(argv: readonly string[], io: CliIO): Promise<number> {
  let json = argv.includes('--json');
  const protocolIndex = argv.indexOf('mcp');
  let protocolMode = protocolIndex >= 0 && argv.slice(0, protocolIndex).every((argument) => argument.startsWith('--'));
  try {
    let argumentsValue: ReturnType<typeof parseArgs<{ options: typeof cliOptions; allowPositionals: true }>>;
    try {
      argumentsValue = parseArgs({
        args: [...argv],
        options: cliOptions,
        allowPositionals: true,
        strict: true,
      });
    } catch {
      return emitFailure(io, json && !protocolMode, failure('invalid-input', 'Invalid command-line options. Use --help for supported syntax.'));
    }
    const { values, positionals } = argumentsValue;
    json = values.json ?? false;
    protocolMode = positionals[0] === 'mcp';
    if (protocolMode) {
      json = false;
      if (positionals.length !== 1 || Object.keys(values).some((key) => key !== 'no-telemetry')) {
        return emitFailure(io, false, failure('invalid-input', 'Use mcp [--no-telemetry]; stdout is reserved for MCP protocol messages.'));
      }
      await serveMissionSpecStdio({ root: process.cwd(), version: await distributedVersion() });
      return 0;
    }
    if (values.help || positionals.length === 0 && !values.version) {
      if (json) io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value: { help } })}\n`);
      else io.stdout(help);
      return 0;
    }
    if (values.version) {
      const version = await distributedVersion();
      io.stdout(json ? `${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value: { version } })}\n` : `${version}\n`);
      return 0;
    }
    const command = positionals[0];
    if (command === 'state') {
      const value = await runStateCommand(positionals, values);
      io.stdout(`${JSON.stringify(json ? { contractVersion: CONTRACT_VERSION, status: 'ok', value } : value, null, json ? undefined : 2)}\n`);
      return 0;
    }
    if (command === 'telemetry' || command === 'logs') {
      const value = await runObservabilityCommand(positionals, values);
      if (typeof value === 'object' && value !== null && 'state' in value && value.state === 'unavailable') {
        const outcome = failure('capability-unavailable', 'The requested observability control is unavailable; no success is assumed.', true);
        if (json) io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, ...outcome, value })}\n`);
        else io.stderr('capability-unavailable: the observability control could not complete. Inspect telemetry status or the explicit pruning preview.\n');
        return 2;
      }
      io.stdout(`${JSON.stringify(json ? { contractVersion: CONTRACT_VERSION, status: 'ok', value } : value, null, json ? undefined : 2)}\n`);
      return 0;
    }
    if (reviewCommands.some((review) => review === command)) {
      const value = await observeCliOperation(positionals, values, await distributedVersion(), () => runReviewCommand(positionals, values));
      io.stdout(`${JSON.stringify(json ? { contractVersion: CONTRACT_VERSION, status: 'ok', value } : value, null, json ? undefined : 2)}\n`);
      return 0;
    }
    if (command === 'run' && positionals[1] === 'status') {
      if (positionals.length !== 3 || Object.keys(values).some((key) => !['json', 'no-telemetry'].includes(key))) {
        return emitFailure(io, json, failure('invalid-input', 'Use run status <RUN-id>.'));
      }
      const value = await runLocalCommand(['run-status', positionals[2]!], values);
      io.stdout(`${JSON.stringify(json ? { contractVersion: CONTRACT_VERSION, status: 'ok', value } : value, null, json ? undefined : 2)}\n`);
      return 0;
    }
    if (command === 'skills' && ['inspect', 'install', 'update', 'remove'].includes(positionals[1] ?? '')) {
      if (positionals.length !== 2 || Object.keys(values).some((key) => !['json', 'no-telemetry', 'host', 'hosts', 'preview', 'approval'].includes(key))) {
        return emitFailure(io, json, failure('invalid-input', 'An option does not apply to skill installation.'));
      }
      const value = await runSkillInstallation(positionals[1]!, values, await distributedVersion());
      io.stdout(`${JSON.stringify(json ? { contractVersion: CONTRACT_VERSION, status: 'ok', value } : value, null, json ? undefined : 2)}\n`);
      return 0;
    }
    if (values.hosts !== undefined) return emitFailure(io, json, failure('invalid-input', 'Repeated host selections apply only to skill installation.'));
    if (localCommands.some((operation) => operation === command)) {
      if (values.host !== undefined || values.operation !== undefined || values.auto !== undefined) return emitFailure(io, json, failure('invalid-input', 'Host rendering/execution flags do not apply to local workflows.'));
      const value = await observeCliOperation(positionals, values, await distributedVersion(), () => runLocalCommand(positionals, values));
      io.stdout(json ? `${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value })}\n` : `${JSON.stringify(value, null, 2)}\n`);
      return 0;
    }
    if (['run', 'pause', 'resume', 'cancel', 'implement'].includes(command ?? '')) {
      return emitFailure(io, json, failure('host-unqualified', 'No native coding host version currently provides qualified hard effect, limit, cancellation and durable dispatch-fencing guarantees. Local terminal approval alone cannot enable dispatch.', true));
    }
    if (['preview', 'profile', 'artifact', 'spec', 'source', 'run', 'evidence', 'acceptance', 'outcome', 'approval', 'reason', 'required', 'file', 'registration', 'task', 'auto', 'verification-plan'].some((option) => Object.hasOwn(values, option))) {
      return emitFailure(io, json, failure('invalid-input', 'Local workflow options do not apply to this command.'));
    }
    if (command === 'validate') {
      if (positionals.length < 2 || values.host !== undefined || values.operation !== undefined) {
        return emitFailure(io, json, failure('invalid-input', 'Validation requires explicit workspace-relative Markdown paths and no host/render options.'));
      }
      const sources = await readMarkdownSources(process.cwd(), positionals.slice(1));
      const validation = parseMarkdownSet(sources);
      const documents = validation.state === 'valid' ? validation.documents : validation.parsedDocuments;
      const value = {
        scope: 'supplied-document-set',
        state: validation.state,
        documents: documents.map((document) => ({
          id: document.id, kind: document.kind, path: document.path,
          rawRevision: document.rawRevision, intentRevision: document.intentRevision,
        })),
        diagnostics: validation.state === 'invalid' ? validation.diagnostics : [],
        implementationVerified: false,
        authorityIssued: false,
      };
      if (json) {
        io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: validation.state === 'valid' ? 'ok' : 'failed', value })}\n`);
      } else {
        io.stdout(`Supplied document set: ${validation.state}; ${documents.length} parsed document(s).\nThis is structural validation, not workflow readiness, implementation verification, or approval.\n`);
        for (const diagnostic of value.diagnostics) {
          io.stderr(`${diagnostic.code}: ${diagnostic.location.path ?? '(source)'}:${diagnostic.location.line}:${diagnostic.location.column}: ${diagnostic.message}\n`);
        }
      }
      return validation.state === 'valid' ? 0 : 1;
    }
    const isCapabilities = command === 'capabilities' && positionals.length === 1;
    const isList = command === 'skills' && positionals[1] === 'list' && positionals.length === 2;
    const isRender = command === 'skills' && positionals[1] === 'render' && positionals.length === 2;
    if ((!isCapabilities && !isList && !isRender) || (!isRender && (values.host !== undefined || values.operation !== undefined))) {
      return emitFailure(io, json, failure('invalid-input', 'Unsupported command or options. Use --help.'));
    }
    if (isRender && (values.host === undefined || values.operation === undefined)) {
      return emitFailure(io, json, failure('invalid-input', 'Rendering requires both --host and --operation.'));
    }
    const catalog = await loadPackagedSkillCatalog();
    const version = await distributedVersion();
    if (isRender) {
      const rendered = renderSkill(catalog, values.host, values.operation, version);
      if (json) {
        io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value: { ...rendered, installed: false, hostQualified: false } })}\n`);
      } else {
        io.stdout(rendered.content);
      }
    } else if (isList) {
      const skills = OPERATION_IDS.map((id) => ({
        id,
        name: OPERATIONS[id].nativeName,
        category: OPERATIONS[id].class,
        description: catalog.manifest.operations[id].description,
        sourceAvailable: true,
        executionAvailable: false,
      }));
      if (json) io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value: { catalogRevision: catalog.revision, skills } })}\n`);
      else {
        io.stdout('Canonical skill sources (not installed or execution-qualified):\n');
        for (const skill of skills) io.stdout(`${skill.id} [${skill.category}] - ${skill.description}\n`);
      }
    } else {
      const capabilities = {
        version,
        stage: 'local-workflow',
        utilities: ['capabilities', 'skills:list', 'skills:render', 'skills:inspect', 'skills:install', 'skills:update', 'skills:remove', 'validate:supplied-document-set', 'mcp', 'telemetry', 'logs', 'state', ...localCommands, ...reviewCommands],
        mcpTransport: 'stdio',
        mcpConfirmation: 'independent-reviewer-only-not-arbitrary-client-accept',
        engines: ENGINE_IDS.map((id) => ({
          id, contractsAvailable: true, localImplementationAvailable: true,
          qualification: id === 'execution' ? 'injected-qualified-host-required' : 'local-component',
        })),
        skills: OPERATION_IDS,
        hosts: catalog.manifest.hosts.map((host) => ({ host, renderingAvailable: true, qualifiedVersions: [] })),
        installedByThisCommand: false,
        executionAvailable: false,
        approvalIssuanceAvailable: true,
        approvalChannel: 'interactive-local-terminal-only',
        checkCollection: 'explicitly-registered-trusted-local-processes',
        generatedSourceApplication: 'inert-proposal-then-exact-source-apply-review',
        autoEffectModel: 'precomputed-exact-byte-transitions-only',
        skillInstallationAvailable: true,
        telemetryTransportAvailable: false,
        telemetryControlsAvailable: true,
        localDiagnostics: 'sanitized-console-only',
        catalogRevision: catalog.revision,
      };
      if (json) io.stdout(`${JSON.stringify({ contractVersion: CONTRACT_VERSION, status: 'ok', value: capabilities })}\n`);
      else io.stdout(`MissionSpec ${version}: reviewed local editing, explicit check registration/collection, retained-evidence review and guided closure available.\nLocal terminal confirmation is not organization identity or adversarial confinement. Native coding-host execution remains unqualified.\n`);
    }
    return 0;
  } catch (error) {
    const outcome = error instanceof WorkflowError
      ? failure(error.code, error.message, true)
      : error instanceof ArtifactReadError
      ? failure(error.code, error.message)
      : error instanceof ContractError
      ? failure('invalid-input', error.message)
      : failure('not-found', 'Distribution resources are missing, invalid, or unreadable. Rebuild the development package or restore its verified files.');
    return emitFailure(io, json && !protocolMode, outcome);
  }
}

if (import.meta.main) {
  let outputUnavailable = false;
  process.stderr.on('error', () => {
    outputUnavailable = true;
    process.exitCode = 1;
  });
  process.stdout.on('error', () => {
    if (!outputUnavailable) process.stderr.write('output-unavailable: could not write command output.\n');
    outputUnavailable = true;
    process.exitCode = 1;
  });
  const result = await runCli(process.argv.slice(2), {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
  });
  process.exitCode = outputUnavailable ? 1 : result;
}
