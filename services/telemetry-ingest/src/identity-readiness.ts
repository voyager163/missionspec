import type { AccessToken, TokenCredential } from '@azure/identity';
import type { StorageReadiness } from './contract.js';

export const INGESTION_SCOPE = 'https://monitor.azure.com/.default';
export const STORAGE_SCOPE = 'https://storage.azure.com/.default';
// Leave ten seconds of the existing 30-second startup probe window for process/listener startup.
export const IDENTITY_PREPARATION_TIMEOUT_MS = 20000;
// Match the pinned bearer policy's refresh window, inside MSAL's five-minute cache renewal window.
export const IDENTITY_REFRESH_MARGIN_MS = 120000;

/** Inert until enabled by the listening receiver. Only this controller calls the MI credential. */
export function createIdentityReadiness(source: TokenCredential, scope: typeof INGESTION_SCOPE | typeof STORAGE_SCOPE = INGESTION_SCOPE): {
  credential: TokenCredential;
  readiness: StorageReadiness;
} {
  let enabled = false;
  let stopped = false;
  let state: 'idle' | 'preparing' | 'ready' | 'failed' = 'idle';
  let token: AccessToken | undefined;
  let usableUntil = 0;
  let pending: AbortController | undefined;

  const refreshAt = (value: AccessToken): number => Math.min(
    value.expiresOnTimestamp - IDENTITY_REFRESH_MARGIN_MS,
    value.refreshAfterTimestamp ?? Infinity,
  );
  const fail = () => {
    state = 'failed';
    pending?.abort();
  };
  function prepare(): void {
    if (!enabled || stopped || pending || state === 'failed') return;
    state = 'preparing';
    const controller = new AbortController();
    pending = controller;
    const deadline = performance.now() + IDENTITY_PREPARATION_TIMEOUT_MS;
    const timer = setTimeout(fail, IDENTITY_PREPARATION_TIMEOUT_MS);
    const checkDeadline = () => {
      controller.signal.throwIfAborted();
      if (performance.now() >= deadline) throw new Error('IDENTITY_NOT_READY');
    };
    void Promise.resolve().then(async () => {
      checkDeadline();
      let value = await source.getToken(scope, { abortSignal: controller.signal });
      checkDeadline();
      // Pinned MSAL may return the old token after awaiting a refreshOn renewal. Read its
      // updated cache once, under the same deadline; never poll/retry a failed acquisition.
      if (value && value.refreshAfterTimestamp !== undefined &&
          value.refreshAfterTimestamp <= Date.now() &&
          value.expiresOnTimestamp - IDENTITY_REFRESH_MARGIN_MS > Date.now()) {
        value = await source.getToken(scope, { abortSignal: controller.signal });
        checkDeadline();
      }
      if (!value || typeof value.token !== 'string' || !value.token ||
          !Number.isFinite(value.expiresOnTimestamp) ||
          !Number.isFinite(refreshAt(value)) || refreshAt(value) <= Date.now()) {
        throw new Error('IDENTITY_NOT_READY');
      }
      return value;
    }).then(value => {
      if (state !== 'preparing' || !enabled || stopped || controller.signal.aborted ||
          performance.now() >= deadline) {
        fail();
        return;
      }
      token = value;
      usableUntil = refreshAt(value);
      state = 'ready';
    }, fail).finally(() => {
      clearTimeout(timer);
      // A deadline closes admission, but does not release the one work slot until settlement.
      pending = undefined;
    });
  }
  const readiness: StorageReadiness = {
    setEnabled(value) {
      enabled = value;
      if (!value) {
        if (pending) fail();
      } else if (!stopped && (state === 'idle' || (state === 'ready' && Date.now() >= usableUntil))) {
        prepare();
      }
    },
    ready() {
      if (!enabled || stopped) return false;
      if (state === 'ready' && Date.now() >= usableUntil) prepare();
      return state === 'ready' && Date.now() < usableUntil;
    },
    stop() {
      stopped = true;
      enabled = false;
      fail();
      token = undefined;
    },
  };
  const credential: TokenCredential = {
    async getToken(scopes, options) {
      const requested = typeof scopes === 'string' ? [scopes] : scopes;
      if (requested.length !== 1 || requested[0] !== scope || options?.claims || options?.tenantId ||
          options?.abortSignal?.aborted || !enabled || stopped || !token ||
          token.expiresOnTimestamp <= Date.now()) throw new Error('IDENTITY_NOT_READY');
      // Admission owns renewal, never an event's 650 ms budget. Already-admitted work may
      // still use this real, unexpired token during renewal; readiness does not revoke it.
      return token;
    },
  };
  return { credential, readiness };
}
