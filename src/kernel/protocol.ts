import { ContractError } from './validation.js';

export const CONTRACT_VERSION = 1 as const;
export type ContractVersion = typeof CONTRACT_VERSION;

export interface Versioned {
  readonly contractVersion: ContractVersion;
}

export function parseContractVersion(value: unknown): ContractVersion {
  if (value !== CONTRACT_VERSION) {
    throw new ContractError('contractVersion', 'unsupported contract version');
  }
  return value;
}
