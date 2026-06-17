// Sparse-fetch the shared @weft/site-kit into ./vendor/site-kit/.
//
// npm cannot install a git SUBDIRECTORY of a different repo directly, so the
// validated pattern (IA §1.3, §6 — "git subdirectory dependency") is to
// sparse-checkout just packages/site-kit out of the weft hub repo into a
// vendored copy that package.json then references as `file:./vendor/site-kit`.
//
// The vendor copy is regenerated (gitignored), never committed — so it always
// refreshes from the hub. This runs as the `preinstall` hook (so the file: dep
// resolves on `npm install`) and is also invoked directly by the Pages workflow
// before install.
//
// Local-dev fallback: if the network clone fails but a sibling weft checkout is
// present next to this repo, vendor from there so an offline `npm install`/build
// still works. CI always has the network and uses the clone path.
import { cp, rm, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = join(here, '..');
const dest = join(siteRoot, 'vendor', 'site-kit');

const REPO = 'https://github.com/foundryside-dev/weft.git';
const SUBDIR = 'packages/site-kit';

const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { stdio: 'inherit', ...opts });

async function vendorFrom(srcKit) {
  await rm(dest, { recursive: true, force: true });
  await mkdir(dirname(dest), { recursive: true });
  await cp(srcKit, dest, { recursive: true });
}

async function fetchViaClone() {
  const tmp = join(tmpdir(), `weft-site-kit-${process.pid}-${Date.now()}`);
  try {
    run('git', ['clone', '--depth', '1', '--filter=blob:none', '--sparse', REPO, tmp]);
    run('git', ['-C', tmp, 'sparse-checkout', 'set', SUBDIR]);
    const srcKit = join(tmp, SUBDIR);
    if (!existsSync(srcKit)) {
      throw new Error(`sparse checkout did not produce ${SUBDIR}`);
    }
    await vendorFrom(srcKit);
    console.log(`[fetch-site-kit] sparse-fetched ${SUBDIR} from ${REPO} -> ${dest}`);
    return true;
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

async function fetchViaSibling() {
  // legis/site -> legis -> <parent> -> weft/packages/site-kit
  const candidates = [
    join(siteRoot, '..', '..', 'weft', SUBDIR),
    join(siteRoot, '..', '..', '..', 'weft', SUBDIR),
  ];
  const srcKit = candidates.find((p) => existsSync(p));
  if (!srcKit) return false;
  await vendorFrom(srcKit);
  console.log(`[fetch-site-kit] (offline fallback) vendored from sibling checkout ${srcKit} -> ${dest}`);
  return true;
}

try {
  await fetchViaClone();
} catch (err) {
  console.warn(`[fetch-site-kit] network clone failed (${err.message}); trying a local sibling weft checkout…`);
  const ok = await fetchViaSibling();
  if (!ok) {
    console.error(
      '[fetch-site-kit] could not fetch @weft/site-kit: the git clone failed and no sibling ' +
        'weft checkout was found. Provide network access (CI path) or a ../weft checkout.',
    );
    process.exit(1);
  }
}
