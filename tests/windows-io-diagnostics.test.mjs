import assert from 'node:assert/strict';
import test from 'node:test';
import { windowsIoDetail } from '../dist/adapters/filesystem/local-workspace.js';
import { WindowsDirectoryDurabilityError, WindowsPrivateStateError } from '../dist/adapters/platform/windows-private-state.js';

test('workspace lock diagnostics retain only immutable native fields and allowlisted filesystem codes', () => {
  const native = new WindowsPrivateStateError({
    reason: 'effect-open', phase: 'file-operation', boundary: 'private', line: 125, nativeStatus: -1073741772,
  });
  native.message = 'PRIVATE path and credentials';
  assert.match(windowsIoDetail(native), /effect-open.*phase=file-operation.*boundary=private.*line=125.*nativeStatus=-1073741772/u);
  for (const error of [
    native,
    new WindowsPrivateStateError('PRIVATE unrecognized native message'),
    new WindowsDirectoryDurabilityError('PRIVATE untrusted detail'),
    Object.assign(new Error('PRIVATE operating system text'), { code: 'EPERM' }),
    Object.assign(new Error('PRIVATE unknown error'), { code: 'PRIVATE' }),
  ]) assert.doesNotMatch(windowsIoDetail(error), /PRIVATE/u);
  assert.equal(windowsIoDetail(Object.assign(new Error('ignored'), { code: 'EBUSY' })), 'Filesystem code: EBUSY.');
  assert.equal(windowsIoDetail(new WindowsDirectoryDurabilityError()), 'Windows directory durability is unconfirmed.');
});
