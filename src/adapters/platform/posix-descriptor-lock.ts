import { createRequire } from 'node:module';
import { WorkflowError } from '../../application/errors.js';

interface DescriptorLock {
  tryLock(descriptor: number): boolean;
  unlock(descriptor: number): void;
}

const require = createRequire(import.meta.url);
let loaded: DescriptorLock | undefined;

/** Lazy POSIX-only native admission; a missing/incompatible prebuild is never a fallback lock. */
export function posixDescriptorLock(): DescriptorLock {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (!['darwin', 'linux'].includes(process.platform) || !['arm64', 'x64'].includes(process.arch) ||
      process.getuid === undefined || major !== 24 || minor === undefined || !Number.isInteger(minor) || minor < 21) {
    throw new WorkflowError('capability-unavailable', 'Native descriptor locks require qualified POSIX arm64/x64 and Node >=24.21.0 <25.');
  }
  if (loaded !== undefined) return loaded;
  try {
    const metadata: unknown = require('fs-native-extensions/package.json');
    if (typeof metadata !== 'object' || metadata === null ||
        Reflect.get(metadata, 'name') !== 'fs-native-extensions' || Reflect.get(metadata, 'version') !== '1.5.1') {
      throw new Error('Unqualified native lock version');
    }
    const addon: unknown = require('fs-native-extensions');
    if (typeof addon !== 'object' || addon === null) throw new Error('Invalid native lock module');
    const tryLock: unknown = Reflect.get(addon, 'tryLock');
    const unlock: unknown = Reflect.get(addon, 'unlock');
    if (typeof tryLock !== 'function' || typeof unlock !== 'function') throw new Error('Invalid native lock contract');
    loaded = {
      tryLock(descriptor) {
        const result: unknown = tryLock(descriptor);
        if (typeof result !== 'boolean') throw new WorkflowError('capability-unavailable', 'Native descriptor lock returned an unknown admission outcome.');
        return result;
      },
      unlock(descriptor) {
        const result: unknown = unlock(descriptor);
        if (result !== undefined) throw new WorkflowError('effect-outcome-unknown', 'Native descriptor unlock returned an unknown outcome.');
      },
    };
    return loaded;
  } catch {
    throw new WorkflowError('capability-unavailable', 'The pinned native descriptor-lock prebuild is unavailable or incompatible; no writer effect is admitted.');
  }
}
