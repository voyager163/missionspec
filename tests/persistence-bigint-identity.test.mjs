import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { failure } from '../dist/adapters/persistence/failures.js';
import { WindowsPrivateStateError } from '../dist/adapters/platform/windows-private-state.js';

test('store file/directory identities never round uint64 values through number Stats', {
  skip: !['darwin', 'linux'].includes(process.platform), timeout: 30_000,
}, (t) => {
  const root = path.join(process.cwd(), `.bigint-store-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import fs from 'node:fs';
    import path from 'node:path';
    import {syncBuiltinESMExports} from 'node:module';
    import {DatabaseSync} from 'node:sqlite';
    import {prepareFiles,checkFiles} from './dist/adapters/persistence/filesystem.js';
    import {readPrivateBytes} from './dist/adapters/persistence/private-reader.js';
    const root=process.argv[1], directory=path.join(root,'.missionspec/state');
    fs.mkdirSync(path.dirname(directory),{mode:0o700});
    fs.mkdirSync(directory,{mode:0o700});
    const filename=path.join(directory,'ledger.sqlite');
    fs.writeFileSync(filename,'',{mode:0o600});
    const db=new DatabaseSync(filename);
    db.exec('CREATE TABLE identity_fixture(value INTEGER)');
    db.close();
    const original={...fs}, real=original.lstatSync(filename,{bigint:true});
    const first=0x20000000000000n, adjacent=first+1n;
    let observed=first;
    assert.equal(Number(first),Number(adjacent),'Fixture must exercise indistinguishable number values');
    // Synthetic uint64 observations exercise numeric precision, not Windows ACL qualification.
    fs.lstatSync=(p,options)=>{
      const result=original.lstatSync(p,options);
      if(p===filename || p===directory) result.ino=options?.bigint?observed:Number(observed);
      return result;
    };
    fs.fstatSync=(fd,options)=>{
      const result=original.fstatSync(fd,options);
      if(String(result.ino)===String(real.ino)) result.ino=options?.bigint?observed:Number(observed);
      return result;
    };
    syncBuiltinESMExports();
    const files=prepareFiles({directory,workspaceRoot:root,
      expectedWorkspace:{workspaceId:'WSP-bigint-fixture',rootDigest:'sha256:'+'a'.repeat(64)},mode:'read-only',busyTimeoutMs:0});
    assert.equal(files.identity.ino,first);
    assert.equal(files.directoryIdentity.ino,first);
    assert.equal(typeof files.identity.dev,'bigint');
    checkFiles(files);
    observed=adjacent;
    assert.throws(()=>checkFiles(files),error=>error.kind==='unavailable');
    assert.throws(()=>readPrivateBytes(filename,100,{expected:{dev:files.identity.dev,ino:Number(adjacent)},prefix:true}),
      error=>error.kind==='stale-revision');
  `, root], { cwd: process.cwd(), encoding: 'utf8', timeout: 15_000, maxBuffer: 32_768 });
  assert.equal(child.status, 0, child.stderr);
});

test('only the exact native SQLite lock-conflict diagnostic becomes a busy store outcome', () => {
  const known = new WindowsPrivateStateError({ reason: 'sqlite-read-busy', phase: 'sqlite-read-lock', nativeStatus: 33 });
  assert.deepEqual(failure(known).error.fields, ['runtimeStore', 'busy']);
  known.message = 'a mutable diagnostic is not the native outcome';
  assert.deepEqual(failure(known).error.fields, ['runtimeStore', 'busy']);
  for (const details of [
    { reason: 'sqlite-read-busy' },
    { reason: 'sqlite-read-busy', phase: 'sqlite-read-lock', nativeStatus: 5 },
    { reason: 'sqlite-read-lock', phase: 'sqlite-read-lock', nativeStatus: 33 },
  ]) {
    assert.deepEqual(failure(new WindowsPrivateStateError(details)).error.fields, ['runtimeStore', 'unavailable']);
  }
});
