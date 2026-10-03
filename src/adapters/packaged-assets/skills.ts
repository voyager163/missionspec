import { open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SkillCatalog } from '../../engines/integration/index.js';
import { OPERATION_IDS } from '../../kernel/registry.js';
import { ContractError } from '../../kernel/validation.js';

const defaultAssetsRoot = fileURLToPath(new URL('../../../assets/', import.meta.url));

async function readAsset(root: string, relative: string, limit: number): Promise<string> {
  const resolved = await realpath(path.join(root, relative));
  const local = path.relative(root, resolved);
  if (local === '..' || local.startsWith(`..${path.sep}`) || path.isAbsolute(local)) {
    throw new ContractError('asset.path', 'resolved asset is outside its package');
  }
  const handle = await open(resolved, 'r');
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > limit) throw new ContractError('asset', 'expected a bounded regular file');
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await handle.read(bytes, length, bytes.length - length, null);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length > limit) throw new ContractError('asset', 'byte limit exceeded');
    try {
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
    } catch {
      throw new ContractError('asset.encoding', 'expected valid UTF-8');
    }
  } finally {
    await handle.close();
  }
}

export async function loadPackagedSkillCatalog(assetsRoot = defaultAssetsRoot): Promise<SkillCatalog> {
  const root = await realpath(assetsRoot);
  const [manifest, schema, entries] = await Promise.all([
    readAsset(root, 'operations/manifest.yaml', 1_000_000),
    readAsset(root, 'schemas/operation-manifest.schema.json', 1_000_000),
    Promise.all(OPERATION_IDS.map(async (id) =>
      [id, await readAsset(root, `operations/${id}.md`, 131_072)] as const)),
  ]);
  return SkillCatalog.parse(manifest, schema, Object.fromEntries(entries));
}
