// Isolated child-process wrapper around published @utexo/rgb-lightning-node-nodejs@0.2.0-beta.5
// using strict NativeExternalSigner (permissiveSignerPolicy: false).
// Supports real SIGKILL crash injection and clean cold restart via POSIX process groups.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pkgRoot = process.env.SHZ_UTEXO_PKG_ROOT || path.resolve(process.cwd(), 'utexo-pkg');
const native = require(path.join(pkgRoot, 'node_modules/@utexo/rgb-lightning-node-nodejs'));

const directory = process.argv[2];
if (!directory) throw new Error('worker directory required');

let signer = null;
let node = null;
let busy = false;

const encode = value => JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
const publish = value => {
  const tmp = path.join(directory, 'response.tmp');
  fs.writeFileSync(tmp, encode(value), { mode: 0o600 });
  fs.renameSync(tmp, path.join(directory, 'response.json'));
};

async function dispatch({ target, method, args = [] }) {
  if (target === 'control') {
    if (method === 'init') {
      const [cfg, seedHex, unlockReq] = args;
      if (cfg.network && String(cfg.network).toLowerCase() !== 'regtest') {
        throw new Error('refusing non-regtest network');
      }
      const signerDir = path.join(cfg.dataDir, 'vls-signer');
      const rlnDir = path.join(cfg.dataDir, 'rln');
      fs.mkdirSync(signerDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(rlnDir, { recursive: true, mode: 0o700 });
      const permissive = cfg.permissiveSignerPolicy === true;
      signer = native.NativeExternalSigner.createWithStorage(seedHex, 'regtest', signerDir, permissive);
      node = native.SdkNode.create({
        data_dir: rlnDir,
        network: 'Regtest',
        daemon_listening_port: 0,
        ldk_peer_listening_port: cfg.ldkPeerListeningPort,
        disable_authentication: true,
        permissive_signer_policy: permissive,
      });
      const initializedMarker = path.join(rlnDir, 'initialized.marker');
      if (!fs.existsSync(initializedMarker)) {
        node.initWithNativeExternalSigner(signer);
        fs.writeFileSync(initializedMarker, '1', { mode: 0o600 });
      }
      node.unlockWithNativeExternalSigner(signer, unlockReq);
      return {
        runtime: native.getRuntimeInfo(),
        node: node.nodeInfo(),
        network: node.networkInfo(),
        address: node.address().address,
      };
    }
    if (method === 'stop') {
      if (node) {
        try { node.shutdown(); } catch {}
        node = null;
      }
      if (signer) {
        try { signer.shutdown(); } catch {}
        signer = null;
      }
      return { stopped: true };
    }
    throw new Error(`unknown control method: ${method}`);
  }
  if (!node || typeof node[method] !== 'function') {
    throw new Error(`unknown native method: ${method}`);
  }
  return node[method](...args);
}

fs.writeFileSync(path.join(directory, 'ready'), 'ready', { mode: 0o600 });
const timer = setInterval(async () => {
  const reqPath = path.join(directory, 'request.json');
  if (busy || !fs.existsSync(reqPath)) return;
  busy = true;
  let request;
  try {
    request = JSON.parse(fs.readFileSync(reqPath, 'utf8'));
    fs.unlinkSync(reqPath);
    const actTmp = path.join(directory, 'active.tmp');
    fs.writeFileSync(actTmp, JSON.stringify({ id: request.id, target: request.target, method: request.method, startedAt: Date.now() }), { mode: 0o600 });
    fs.renameSync(actTmp, path.join(directory, 'active.json'));
    const result = await dispatch(request);
    publish({ id: request.id, ok: true, result: result ?? null });
  } catch (err) {
    publish({ id: request?.id, ok: false, error: { name: err.name, message: err.message, code: err.code } });
  } finally {
    busy = false;
  }
  if (request?.target === 'control' && request.method === 'stop') {
    clearInterval(timer);
    process.exit(0);
  }
}, 10);
