import type { NativeHost } from '../../kernel/identifiers.js';
import type { ContentDigest } from '../../kernel/revisions.js';
import type { Outcome } from '../../kernel/outcomes.js';

export const NATIVE_PROPOSAL_PINS = Object.freeze({
  copilot: Object.freeze({
    cli: '1.0.85', sdk: '@github/copilot-sdk', sdkVersion: '1.0.14', protocolVersion: 3,
    sourceRevision: 'e60d9037353249ef16b349eb4012e8c1d113fda5',
  }),
  codex: Object.freeze({
    cli: '0.155.1', sourceRevision: 'be2951ea34f0d295ed0becf97079f92fa5f6950e',
  }),
  claude: Object.freeze({
    cli: '2.1.278', sdk: '@anthropic-ai/claude-agent-sdk', sdkVersion: '0.3.278',
    sourceRevision: '18661edde4498f76ff5599b17ee4ca81d98409b2',
  }),
});

export interface NativeStartReview {
  readonly host: NativeHost;
  readonly requiredCliVersion: string;
  readonly executable: string;
  readonly executableDigest: ContentDigest;
  readonly sdk: { readonly name: string; readonly version: string; readonly manifestDigest: ContentDigest } | null;
  readonly requestDigest: ContentDigest;
  readonly configurationDigest: ContentDigest;
  readonly guarantees: 'restricted-proposals-only';
}

/**
 * A trusted local composition boundary, not host qualification or an effect grant.
 * No environment is inherited and no model invocation is authorized by default.
 */
export interface NativeHostSetup {
  readonly executable: string;
  readonly workingDirectory: string;
  readonly homeDirectory: string;
  readonly environment: Readonly<Record<string, string>>;
  readonly model: string;
  readonly authorizeNativeStart: (review: NativeStartReview) => Promise<Outcome<{ readonly allowed: boolean }>>;
}

export interface ExternalSdkIdentity {
  /** Absolute package.json of the very module used by the injected factory. */
  readonly packageJsonPath: string;
}

export class NativeBridgeError extends Error {
  constructor(
    readonly code: 'invalid-input' | 'unsupported-version' | 'capability-unavailable' | 'authority-required' |
      'scope-exceeded' | 'limit-reached' | 'effect-outcome-unknown',
    message: string,
  ) {
    super(message);
    this.name = 'NativeBridgeError';
  }
}
