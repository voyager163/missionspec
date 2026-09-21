import { randomBytes } from 'node:crypto';
import { isatty } from 'node:tty';
import { createInterface } from 'node:readline';
import type { FilePlan } from '../filesystem/local-workspace.js';
import type { ApprovalReference, ApprovalRequest } from '../../kernel/authority.js';
import type { LocalAuthorityPort } from '../../ports/contracts.js';
import {
  openLocalAuthority, type LocalConfirmationAuthority, type LocalConfirmationDecision,
  type LocalConfirmationReview, type TrustedConfirmationTransport,
} from './local-authority.js';

const terminalTransport: TrustedConfirmationTransport = Object.freeze({
  channel: 'terminal-confirmation',
  protocolIdentity: Object.freeze({ id: 'missionspec.terminal-challenge', version: '1' }),
  async confirm(review: LocalConfirmationReview, signal: AbortSignal): Promise<LocalConfirmationDecision> {
    if (!isatty(0) || !isatty(2) || !process.stdin.isTTY || !process.stderr.isTTY) return 'unavailable';
    if (signal.aborted) return 'cancel';
    const challenge = `confirm ${randomBytes(16).toString('hex')}`;
    const terminal = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    const cancel = () => terminal.close();
    signal.addEventListener('abort', cancel, { once: true });
    try {
      process.stderr.write(`\nLOCAL USER REVIEW — no organization or tamper-proof assurance.\n${review.renderedDisplay}\n`);
      return await new Promise<LocalConfirmationDecision>((resolve) => {
        terminal.once('close', () => resolve('cancel'));
        terminal.once('SIGINT', cancel);
        terminal.question(`Type exactly "${challenge}" to confirm this ${review.action} review; it expires ${review.expiresAt}:\n> `, (answer) => {
          resolve(answer === challenge ? 'accept' : 'decline');
        });
      });
    } finally {
      signal.removeEventListener('abort', cancel);
      terminal.close();
    }
  },
});

/** The terminal is one transport over the shared persistent local-authority backend. */
export class TerminalAuthority implements LocalConfirmationAuthority {
  private constructor(private readonly backend: LocalConfirmationAuthority) {}

  static async open(directory: string): Promise<TerminalAuthority> {
    return new TerminalAuthority(await openLocalAuthority({ directory, transport: terminalTransport }));
  }

  confirmPlan(plan: FilePlan): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    return this.backend.confirmPlan(plan);
  }

  requestConfirmation(request: ApprovalRequest, detail?: Readonly<Record<string, unknown>>): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    return this.backend.requestConfirmation(request, detail);
  }

  resolve(reference: ApprovalReference): ReturnType<LocalAuthorityPort['resolve']> {
    return this.backend.resolve(reference);
  }

  revoke(reference: ApprovalReference): Promise<void> {
    return this.backend.revoke(reference);
  }
}
