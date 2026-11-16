// =============================================================================
// forge — a GitHub-compatible git forge (single file, Node.js stdlib only)
//
// What it is:
//   * A real git object store (SHA-1 loose objects: blob / tree / commit / tag)
//     with refs, packfile read/write (incl. REF_DELTA and OFS_DELTA), and the
//     git smart-HTTP protocol (git-upload-pack / git-receive-pack), so a real
//     `git clone` / `git fetch` / `git push` works against it.
//   * A GitHub-compatible REST API (v3 shape): users, repos, contents,
//     commits, branches, refs, issues (+comments), pull requests (+merge).
//   * A small server-rendered web UI for browsing repos, issues and PRs.
//
// How to run:
//   node main.ts                 run the built-in end-to-end self-test (default)
//   node main.ts --serve         start the forge server (persistent)
//   node main.ts --serve --port 3000 --data ./data
//
//   Env: FORGE_PORT (default 3000), FORGE_DATA_DIR (default ./data),
//        FORGE_HOST (default 127.0.0.1)
//
// The default run is a deterministic self-test: it boots the server on an
// ephemeral port with a throwaway data dir, drives the whole forge through
// its real HTTP + git-protocol surface, prints a fixed PASS summary and
// exits 0. No timestamps, ports or random values appear in its output.
// =============================================================================

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const VERSION = '1.0.0';
const ZERO_SHA = '0000000000000000000000000000000000000000';
const FIXED_TS = 1700000000; // fixed commit timestamp used by the self-test
const FIXED_TZ = '+0000';

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

function sha1hex(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}
function sha1buf(buf) {
  return crypto.createHash('sha1').update(buf).digest();
}
function sha256hex(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}
function isSha(s) {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}
function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function b64encode(buf) {
  return Buffer.from(buf).toString('base64');
}
function b64decode(str) {
  return Buffer.from(String(str), 'base64');
}
function jsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) return resolve({});
      try { resolve(JSON.parse(raw)); }
      catch (e) { reject(new Error('invalid JSON body')); }
    });
    req.on('error', reject);
  });
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}
function sendText(res, status, body, type) {
  res.writeHead(status, { 'content-type': type || 'text/plain; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}
function sendHtml(res, status, body) {
  sendText(res, status, body, 'text/html; charset=utf-8');
}
function mkdirp(dir) {
  fs.mkdirSync(dir, { recursive: true });
}
function writeFileAtomic(file, data) {
  mkdirp(path.dirname(file));
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}
function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
function writeJsonFile(file, obj) {
  writeFileAtomic(file, JSON.stringify(obj, null, 2));
}

// --- pkt-line (git wire format) --------------------------------------------
function pktLine(str) {
  const payload = Buffer.from(str, 'utf8');
  const len = payload.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, payload]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
function parsePktLines(buf) {
  // Returns { lines: string[], rest: Buffer } — stops at flush or end.
  const lines = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (isNaN(len)) break;
    if (len === 0) { off += 4; break; } // flush
    if (off + len > buf.length) break;
    lines.push(buf.toString('utf8', off + 4, off + len));
    off += len;
  }
  return { lines, rest: buf.subarray(off) };
}

// --- packfile varints --------------------------------------------------------
function encodeObjHeader(type, size) {
  // type: 1 commit, 2 tree, 3 blob, 4 tag, 6 ofs-delta, 7 ref-delta
  const out = [];
  let first = (type << 4) | (size & 0x0f);
  size >>>= 4;
  if (size) first |= 0x80;
  out.push(first);
  while (size) {
    let b = size & 0x7f;
    size >>>= 7;
    if (size) b |= 0x80;
    out.push(b);
  }
  return Buffer.from(out);
}
function decodeObjHeader(buf, off) {
  let b = buf[off++];
  const type = (b >> 4) & 0x07;
  let size = b & 0x0f;
  let shift = 4;
  while (b & 0x80) {
    b = buf[off++];
    size |= (b & 0x7f) << shift;
    shift += 7;
  }
  return { type, size, off };
}
function encodeDeltaSize(n) {
  const out = [];
  while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Buffer.from(out);
}
function readDeltaSize(buf, off) {
  let n = 0, shift = 0, b;
  do { b = buf[off++]; n |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
  return { value: n, off };
}
function encodeOfsOffset(offset) {
  // git's negative-offset encoding for OFS_DELTA
  const bytes = [offset & 0x7f];
  offset >>>= 7;
  while (offset) { offset -= 1; bytes.unshift(0x80 | (offset & 0x7f)); offset >>>= 7; }
  return Buffer.from(bytes);
}
function decodeOfsOffset(buf, off) {
  let b = buf[off++];
  let offset = b & 0x7f;
  while (b & 0x80) {
    b = buf[off++];
    offset = ((offset + 1) << 7) | (b & 0x7f);
  }
  return { offset, off };
}

// ---------------------------------------------------------------------------
// JSON store (one file per collection, atomic writes)
// ---------------------------------------------------------------------------

class Store {
  constructor(dir) {
    this.dir = dir;
    mkdirp(dir);
  }
  load(name, fallback) {
    return readJsonFile(path.join(this.dir, name + '.json'), fallback);
  }
  save(name, obj) {
    writeJsonFile(path.join(this.dir, name + '.json'), obj);
  }
}

// ---------------------------------------------------------------------------
// git object store: loose objects + refs (a bare repo on disk)
// ---------------------------------------------------------------------------

const OBJ_TYPE = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const OBJ_TYPE_NUM = { commit: 1, tree: 2, blob: 3, tag: 4 };

class GitRepo {
  constructor(root) {
    this.root = root;
    this.objectsDir = path.join(root, 'objects');
    this.refsDir = path.join(root, 'refs');
  }
  init() {
    mkdirp(path.join(this.objectsDir, 'info'));
    mkdirp(path.join(this.objectsDir, 'pack'));
    mkdirp(path.join(this.refsDir, 'heads'));
    mkdirp(path.join(this.refsDir, 'tags'));
    const head = path.join(this.root, 'HEAD');
    if (!fs.existsSync(head)) fs.writeFileSync(head, 'ref: refs/heads/main\n');
    const cfg = path.join(this.root, 'config');
    if (!fs.existsSync(cfg)) {
      fs.writeFileSync(cfg, '[core]\n\trepositoryformatversion = 0\n\tbare = true\n');
    }
  }
  headRef() {
    try {
      const head = fs.readFileSync(path.join(this.root, 'HEAD'), 'utf8').trim();
      if (head.startsWith('ref: ')) return head.slice(5).trim();
    } catch (e) { /* fall through */ }
    return 'refs/heads/main';
  }
  objectPath(sha) {
    return path.join(this.objectsDir, sha.slice(0, 2), sha.slice(2));
  }
  hasObject(sha) {
    return isSha(sha) && fs.existsSync(this.objectPath(sha));
  }
  readObject(sha) {
    if (!this.hasObject(sha)) return null;
    const raw = zlib.inflateSync(fs.readFileSync(this.objectPath(sha)));
    const nul = raw.indexOf(0);
    const header = raw.toString('ascii', 0, nul).split(' ');
    const type = header[0];
    const size = parseInt(header[1], 10);
    const data = raw.subarray(nul + 1);
    if (data.length !== size) throw new Error('corrupt object ' + sha);
    return { type, data };
  }
  writeObject(type, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const header = Buffer.from(type + ' ' + buf.length + '\0', 'ascii');
    const stored = Buffer.concat([header, buf]);
    const sha = sha1hex(stored);
    const p = this.objectPath(sha);
    if (!fs.existsSync(p)) {
      mkdirp(path.dirname(p));
      fs.writeFileSync(p, zlib.deflateSync(stored));
    }
    return sha;
  }
  writeRawObject(sha, type, data) {
    // store an object whose sha is already known (from a received pack)
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const header = Buffer.from(type + ' ' + buf.length + '\0', 'ascii');
    const p = this.objectPath(sha);
    if (!fs.existsSync(p)) {
      mkdirp(path.dirname(p));
      fs.writeFileSync(p, zlib.deflateSync(Buffer.concat([header, buf])));
    }
    return sha;
  }
  refPath(ref) {
    return path.join(this.root, ref);
  }
  readRef(ref) {
    try {
      const v = fs.readFileSync(this.refPath(ref), 'utf8').trim();
      return isSha(v) ? v : null;
    } catch (e) { return null; }
  }
  writeRef(ref, sha) {
    const p = this.refPath(ref);
    mkdirp(path.dirname(p));
    fs.writeFileSync(p, sha + '\n');
  }
  deleteRef(ref) {
    try { fs.unlinkSync(this.refPath(ref)); } catch (e) { /* already gone */ }
  }
  listRefs(prefix) {
    const out = [];
    const walk = (dir, rel) => {
      if (!fs.existsSync(dir)) return;
      for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        const p = path.join(dir, ent.name);
        const r = rel + ent.name;
        if (ent.isDirectory()) walk(p, r + '/');
        else if (ent.isFile()) {
          const sha = this.readRef(r);
          if (sha) out.push({ ref: r, sha });
        }
      }
    };
    walk(path.join(this.root, 'refs'), 'refs/');
    const head = this.readRef(this.headRef());
    if (head) out.push({ ref: 'HEAD', sha: head });
    return out.filter((r) => !prefix || r.ref.startsWith(prefix)).sort((a, b) => a.ref.localeCompare(b.ref));
  }
  resolveRef(name) {
    if (name === 'HEAD') return this.readRef(this.headRef());
    if (name.startsWith('refs/')) return this.readRef(name);
    return this.readRef('refs/heads/' + name) || this.readRef('refs/tags/' + name);
  }
  defaultBranch() {
    const h = this.headRef();
    return h.startsWith('refs/heads/') ? h.slice('refs/heads/'.length) : 'main';
  }

  // --- trees -----------------------------------------------------------------
  parseTree(sha) {
    const obj = this.readObject(sha);
    if (!obj || obj.type !== 'tree') throw new Error('not a tree: ' + sha);
    const entries = [];
    let off = 0;
    const data = obj.data;
    while (off < data.length) {
      const sp = data.indexOf(0x20, off);
      const nul = data.indexOf(0, sp);
      const mode = data.toString('ascii', off, sp);
      const name = data.toString('utf8', sp + 1, nul);
      const esha = data.subarray(nul + 1, nul + 21).toString('hex');
      entries.push({ mode, name, sha: esha, type: mode === '40000' ? 'tree' : 'blob' });
      off = nul + 21;
    }
    return entries;
  }
  writeTree(entries) {
    // entries: [{mode, name, sha}] — git sorts by name, dirs as name + '/'
    const sorted = entries.slice().sort((a, b) => {
      const an = a.mode === '40000' ? a.name + '/' : a.name;
      const bn = b.mode === '40000' ? b.name + '/' : b.name;
      return an < bn ? -1 : an > bn ? 1 : 0;
    });
    const parts = [];
    for (const e of sorted) {
      parts.push(Buffer.from(e.mode + ' ' + e.name + '\0', 'utf8'));
      parts.push(Buffer.from(e.sha, 'hex'));
    }
    return this.writeObject('tree', Buffer.concat(parts));
  }
  buildTreeFromFiles(files) {
    // files: Map<path, {mode, sha}> — builds nested trees bottom-up
    const build = (dir) => {
      const entries = [];
      const subdirs = new Map();
      for (const [p, f] of files) {
        if (dir && !p.startsWith(dir + '/')) continue;
        const rel = dir ? p.slice(dir.length + 1) : p;
        if (!rel) continue;
        const slash = rel.indexOf('/');
        if (slash === -1) {
          entries.push({ mode: f.mode || '100644', name: rel, sha: f.sha });
        } else {
          const d = rel.slice(0, slash);
          if (!subdirs.has(d)) subdirs.set(d, []);
          subdirs.get(d).push(p);
        }
      }
      for (const [d, paths] of [...subdirs.entries()].sort()) {
        const sub = new Map();
        for (const p of paths) sub.set(p, files.get(p));
        entries.push({ mode: '40000', name: d, sha: build(dir ? dir + '/' + d : d) });
      }
      return this.writeTree(entries);
    };
    return build('');
  }
  flattenTree(treeSha, prefix, out) {
    out = out || new Map();
    for (const e of this.parseTree(treeSha)) {
      const p = prefix ? prefix + '/' + e.name : e.name;
      if (e.type === 'tree') this.flattenTree(e.sha, p, out);
      else out.set(p, { mode: e.mode, sha: e.sha });
    }
    return out;
  }

  // --- commits ---------------------------------------------------------------
  parseCommit(sha) {
    const obj = this.readObject(sha);
    if (!obj || obj.type !== 'commit') throw new Error('not a commit: ' + sha);
    const text = obj.data.toString('utf8');
    const head = text.split('\n\n')[0];
    const message = text.slice(head.length + 2);
    const c = { sha, tree: null, parents: [], author: null, committer: null, message, raw: obj.data };
    for (const line of head.split('\n')) {
      if (line.startsWith('tree ')) c.tree = line.slice(5).trim();
      else if (line.startsWith('parent ')) c.parents.push(line.slice(7).trim());
      else if (line.startsWith('author ')) c.author = line.slice(7);
      else if (line.startsWith('committer ')) c.committer = line.slice(10);
    }
    return c;
  }
  createCommit({ tree, parents, author, committer, message, timestamp }) {
    const ts = timestamp != null ? timestamp : Math.floor(Date.now() / 1000);
    const ident = (who) => who.name + ' <' + who.email + '> ' + ts + ' ' + FIXED_TZ;
    let body = 'tree ' + tree + '\n';
    for (const p of parents || []) body += 'parent ' + p + '\n';
    body += 'author ' + ident(author) + '\n';
    body += 'committer ' + ident(committer) + '\n';
    body += '\n' + message;
    return this.writeObject('commit', Buffer.from(body, 'utf8'));
  }

  // --- graph walk --------------------------------------------------------------
  reachableObjects(startShas) {
    const seen = new Set();
    const stack = (startShas || []).filter(isSha);
    while (stack.length) {
      const sha = stack.pop();
      if (seen.has(sha) || !this.hasObject(sha)) continue;
      seen.add(sha);
      const obj = this.readObject(sha);
      if (obj.type === 'commit') {
        const c = this.parseCommit(sha);
        if (c.tree) stack.push(c.tree);
        for (const p of c.parents) stack.push(p);
      } else if (obj.type === 'tree') {
        for (const e of this.parseTree(sha)) stack.push(e.sha);
      } else if (obj.type === 'tag') {
        const m = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})/m);
        if (m) stack.push(m[1]);
      }
    }
    return seen;
  }
  isAncestor(maybeAncestor, sha) {
    if (maybeAncestor === sha) return true;
    const seen = new Set();
    const stack = [sha];
    while (stack.length) {
      const cur = stack.pop();
      if (!isSha(cur) || seen.has(cur)) continue;
      seen.add(cur);
      if (cur === maybeAncestor) return true;
      try {
        const c = this.parseCommit(cur);
        for (const p of c.parents) stack.push(p);
      } catch (e) { /* not a commit */ }
    }
    return false;
  }
  mergeBase(a, b) {
    // first common ancestor (BFS from both sides, deterministic order)
    const ancA = new Set();
    const stack = [a];
    while (stack.length) {
      const cur = stack.pop();
      if (!isSha(cur) || ancA.has(cur)) continue;
      ancA.add(cur);
      try { for (const p of this.parseCommit(cur).parents) stack.push(p); } catch (e) {}
    }
    const seen = new Set();
    const q = [b];
    while (q.length) {
      const cur = q.shift();
      if (!isSha(cur) || seen.has(cur)) continue;
      seen.add(cur);
      if (ancA.has(cur)) return cur;
      try { for (const p of this.parseCommit(cur).parents) q.push(p); } catch (e) {}
    }
    return null;
  }
  listCommits(fromSha, limit) {
    // deterministic log: newest commit-time first, ties broken by sha
    const seen = new Set();
    const out = [];
    const stack = [fromSha];
    while (stack.length && out.length < (limit || 100)) {
      const sha = stack.pop();
      if (!isSha(sha) || seen.has(sha)) continue;
      seen.add(sha);
      let c;
      try { c = this.parseCommit(sha); } catch (e) { continue; }
      out.push(c);
      for (const p of c.parents) stack.push(p);
    }
    const tsOf = (c) => {
      const m = (c.committer || '').match(/ (\d+) [+-]\d{4}$/);
      return m ? parseInt(m[1], 10) : 0;
    };
    // stable sort: equal timestamps keep walk order (newest first)
    out.sort((x, y) => tsOf(y) - tsOf(x));
    return out;
  }
  commitTime(sha) {
    try {
      const c = this.parseCommit(sha);
      const m = (c.committer || '').match(/ (\d+) [+-]\d{4}$/);
      return m ? parseInt(m[1], 10) : 0;
    } catch (e) { return 0; }
  }
}

// ---------------------------------------------------------------------------
// packfiles: write (full objects only) and parse (incl. deltas)
// ---------------------------------------------------------------------------

function applyDelta(base, delta) {
  let p = 0;
  const bs = readDeltaSize(delta, p); p = bs.off;
  const rs = readDeltaSize(delta, p); p = rs.off;
  if (bs.value !== base.length) throw new Error('delta base size mismatch');
  const parts = [];
  while (p < delta.length) {
    const op = delta[p++];
    if (op & 0x80) {
      let cpOff = 0, cpSize = 0;
      if (op & 0x01) cpOff = delta[p++];
      if (op & 0x02) cpOff |= delta[p++] << 8;
      if (op & 0x04) cpOff |= delta[p++] << 16;
      if (op & 0x08) cpOff |= delta[p++] << 24;
      if (op & 0x10) cpSize = delta[p++];
      if (op & 0x20) cpSize |= delta[p++] << 8;
      if (op & 0x40) cpSize |= delta[p++] << 16;
      if (cpSize === 0) cpSize = 0x10000;
      parts.push(base.subarray(cpOff, cpOff + cpSize));
    } else if (op) {
      parts.push(delta.subarray(p, p + op));
      p += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const res = Buffer.concat(parts);
  if (res.length !== rs.value) throw new Error('delta result size mismatch');
  return res;
}

function writePack(repo, shas) {
  // deterministic order: commits, trees, blobs, tags — each group sorted
  const objs = [];
  for (const sha of shas) {
    const o = repo.readObject(sha);
    if (o) objs.push({ sha, type: o.type, data: o.data });
  }
  const rank = { commit: 0, tree: 1, blob: 2, tag: 3 };
  objs.sort((a, b) => (rank[a.type] - rank[b.type]) || (a.sha < b.sha ? -1 : 1));
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0);
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objs.length, 8);
  parts.push(header);
  for (const o of objs) {
    parts.push(encodeObjHeader(OBJ_TYPE_NUM[o.type], o.data.length));
    parts.push(zlib.deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  const trailer = sha1buf(body);
  return Buffer.concat([body, trailer]);
}

function parsePack(buf, repo) {
  // repo (optional): object store used to resolve thin-pack delta bases —
  // real git clients send thin packs whose delta bases already live on the
  // server, so a REF_DELTA base may not be inside the pack itself.
  if (buf.length < 32 || buf.toString('ascii', 0, 4) !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = buf.readUInt32BE(4);
  const count = buf.readUInt32BE(8);
  if (version !== 2 && version !== 3) throw new Error('unsupported pack version ' + version);
  const entries = []; // {sha?, type, data, offset, deltaBase?}
  let off = 12;
  const byOffset = new Map();
  for (let i = 0; i < count; i++) {
    const start = off;
    const h = decodeObjHeader(buf, off);
    off = h.off;
    let type = h.type;
    let baseSha = null, baseOffset = null;
    if (type === 6) { // OFS_DELTA
      const d = decodeOfsOffset(buf, off);
      off = d.off;
      baseOffset = start - d.offset;
    } else if (type === 7) { // REF_DELTA
      baseSha = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inflated = zlib.inflateSync(buf.subarray(off));
    const len = deflateConsumedLength(buf, off);
    off += len;
    const entry = { type, data: inflated, offset: start, baseSha, baseOffset, sha: null };
    entries.push(entry);
    byOffset.set(start, entry);
  }
  const trailer = buf.subarray(buf.length - 20);
  const expect = sha1buf(buf.subarray(0, buf.length - 20));
  if (!trailer.equals(expect)) throw new Error('pack trailer checksum mismatch');
  // resolve deltas (possibly chained); iterate until stable
  const resolved = new Map(); // sha -> {type, data}
  const resolve = (entry, depth) => {
    if (depth > 50) throw new Error('delta chain too deep');
    if (entry.sha) return entry;
    if (entry.type === 6 || entry.type === 7) {
      let base = null;
      if (entry.type === 6) {
        const b = byOffset.get(entry.baseOffset);
        if (!b) throw new Error('ofs-delta base not in pack');
        base = resolve(b, depth + 1);
      } else {
        base = resolved.get(entry.baseSha);
        if (!base && repo) {
          const robj = repo.readObject(entry.baseSha);
          if (robj) base = { type: OBJ_TYPE_NUM[robj.type], data: robj.data };
        }
        if (!base) throw new Error('ref-delta base not in pack: ' + entry.baseSha);
      }
      const data = applyDelta(base.data, entry.data);
      entry.type = base.type;
      entry.data = data;
    }
    const header = Buffer.from(OBJ_TYPE[entry.type] + ' ' + entry.data.length + '\0', 'ascii');
    entry.sha = sha1hex(Buffer.concat([header, entry.data]));
    resolved.set(entry.sha, entry);
    return entry;
  };
  for (const e of entries) resolve(e, 0);
  return entries.map((e) => ({ sha: e.sha, type: OBJ_TYPE[e.type], data: e.data }));
}

function deflateConsumedLength(buf, off) {
  // Smallest prefix of the zlib stream starting at `off` that inflates
  // cleanly. A truncated stream throws (missing final block / adler check),
  // and any longer prefix inflates the same way, so binary search finds the
  // exact stream end.
  const chunk = buf.subarray(off);
  let lo = 1, hi = chunk.length, best = chunk.length;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      zlib.inflateSync(chunk.subarray(0, mid));
      best = mid;
      hi = mid - 1;
    } catch (e) { lo = mid + 1; }
  }
  return best;
}

// ---------------------------------------------------------------------------
// git smart HTTP protocol (upload-pack / receive-pack)
// ---------------------------------------------------------------------------

function advertiseRefs(repo, service) {
  const refs = repo.listRefs('refs/').filter((r) => r.ref !== 'HEAD');
  const head = repo.readRef(repo.headRef());
  const out = [pktLine('# service=' + service + '\n'), PKT_FLUSH];
  const caps = service === 'git-upload-pack'
    ? 'agent=forge/' + VERSION
    : 'agent=forge/' + VERSION + ' report-status';
  let first = true;
  const emit = (sha, name) => {
    let line = sha + ' ' + name + '\n';
    if (first) { line = sha + ' ' + name + '\0' + caps + '\n'; first = false; }
    out.push(pktLine(line));
  };
  if (head) emit(head, 'HEAD');
  for (const r of refs) emit(r.sha, r.ref);
  if (refs.length === 0 && !head) {
    // empty repo: advertise the default branch as an unborn ref
    out.push(pktLine(ZERO_SHA + ' capabilities^{}\0' + caps + '\n'));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

function handleUploadPack(repo, body) {
  const { lines } = parsePktLines(body);
  const wants = [];
  const haves = [];
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const sha = line.slice(5).split(' ')[0];
      if (isSha(sha)) wants.push(sha);
    } else if (line.startsWith('have ')) {
      const sha = line.slice(5).split(' ')[0];
      if (isSha(sha)) haves.push(sha);
    } else if (line === 'done') break;
  }
  if (wants.length === 0) throw new Error('upload-pack: no wants');
  for (const w of wants) {
    if (!repo.hasObject(w)) throw new Error('upload-pack: want object not found ' + w);
  }
  const wantSet = repo.reachableObjects(wants);
  const haveSet = repo.reachableObjects(haves);
  const toSend = [...wantSet].filter((s) => !haveSet.has(s));
  const pack = writePack(repo, toSend);
  return Buffer.concat([pktLine('NAK\n'), pack]);
}

function handleReceivePack(repo, body) {
  const { lines, rest } = parsePktLines(body);
  const updates = [];
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const clean = nul === -1 ? line : line.slice(0, nul);
    const parts = clean.split(' ');
    if (parts.length >= 3 && isSha(parts[0]) && isSha(parts[1])) {
      updates.push({ oldSha: parts[0], newSha: parts[1], ref: parts[2] });
    }
  }
  let objects;
  try {
    objects = parsePack(rest, repo);
  } catch (e) {
    const out = [pktLine('unpack ' + e.message + '\n')];
    for (const u of updates) out.push(pktLine('ng ' + u.ref + ' ' + e.message + '\n'));
    out.push(PKT_FLUSH);
    return Buffer.concat(out);
  }
  for (const o of objects) repo.writeRawObject(o.sha, o.type, o.data);
  const results = [];
  for (const u of updates) {
    const cur = repo.readRef(u.ref);
    if (u.oldSha !== ZERO_SHA && cur !== u.oldSha) {
      results.push({ ok: false, ref: u.ref, reason: 'old ref mismatch (expected ' + (cur || 'none') + ')' });
      continue;
    }
    if (u.newSha === ZERO_SHA) {
      repo.deleteRef(u.ref);
    } else {
      if (!repo.hasObject(u.newSha)) {
        results.push({ ok: false, ref: u.ref, reason: 'new object not in pack' });
        continue;
      }
      repo.writeRef(u.ref, u.newSha);
    }
    results.push({ ok: true, ref: u.ref });
  }
  const out = [pktLine('unpack ok\n')];
  for (const r of results) {
    out.push(pktLine(r.ok ? 'ok ' + r.ref + '\n' : 'ng ' + r.ref + ' ' + r.reason + '\n'));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

// --- minimal git client helpers (used by the self-test; pure Node) ----------
function buildUploadPackRequest(wants, haves) {
  const parts = [];
  wants.forEach((w, i) => {
    parts.push(pktLine(i === 0 ? 'want ' + w + ' agent=forge/' + VERSION + '\n' : 'want ' + w + '\n'));
  });
  parts.push(PKT_FLUSH);
  for (const h of haves || []) parts.push(pktLine('have ' + h + '\n'));
  parts.push(pktLine('done\n'));
  return Buffer.concat(parts);
}
function parseUploadPackResponse(buf) {
  // skip pkt-lines until the pack starts (after the NAK line)
  let off = 0;
  while (off + 4 <= buf.length) {
    if (buf.toString('ascii', off, off + 4) === 'PACK') break;
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (isNaN(len) || len <= 0) throw new Error('unexpected bytes in upload-pack response');
    off += len;
  }
  if (buf.toString('ascii', off, off + 4) !== 'PACK') throw new Error('no pack in upload-pack response');
  return buf.subarray(off);
}
function buildReceivePackRequest(updates, pack) {
  const parts = [];
  updates.forEach((u, i) => {
    const line = u.oldSha + ' ' + u.newSha + ' ' + u.ref + (i === 0 ? '\0report-status agent=forge/' + VERSION : '') + '\n';
    parts.push(pktLine(line));
  });
  parts.push(PKT_FLUSH);
  parts.push(pack);
  return Buffer.concat(parts);
}
function parseReceivePackResponse(buf) {
  const { lines } = parsePktLines(buf);
  const out = { unpack: null, refs: [] };
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('unpack ')) out.unpack = line.slice(7);
    else if (line.startsWith('ok ')) out.refs.push({ ref: line.slice(3), ok: true });
    else if (line.startsWith('ng ')) {
      const rest = line.slice(3);
      const sp = rest.indexOf(' ');
      out.refs.push({ ref: sp === -1 ? rest : rest.slice(0, sp), ok: false, reason: sp === -1 ? '' : rest.slice(sp + 1) });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Forge: data model + GitHub-compatible operations
// ---------------------------------------------------------------------------

function validLogin(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,38}[a-zA-Z0-9])?$/.test(s);
}
function validRepoName(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9._-]+$/.test(s) && s !== '.' && s !== '..' && !s.includes('..');
}
function slugifyBranch(s) {
  return String(s).replace(/[^a-zA-Z0-9._\-\/]/g, '-');
}

class Forge {
  constructor(dataDir, opts) {
    opts = opts || {};
    this.dataDir = dataDir;
    this.store = new Store(dataDir);
    this.reposDir = path.join(dataDir, 'repos');
    mkdirp(this.reposDir);
    this.nowFn = opts.now || (() => Date.now());
    this.testMode = !!opts.testMode;
    this.users = this.store.load('users', {});
    this.repos = this.store.load('repos', {});
    this.issues = this.store.load('issues', {});
    this.pulls = this.store.load('pulls', {});
    this.counters = this.store.load('counters', { repoId: 1 });
  }
  save() {
    this.store.save('users', this.users);
    this.store.save('repos', this.repos);
    this.store.save('issues', this.issues);
    this.store.save('pulls', this.pulls);
    this.store.save('counters', this.counters);
  }
  nowIso() { return new Date(this.nowFn()).toISOString(); }
  nowTs() { return Math.floor(this.nowFn() / 1000); }
  repoPath(owner, name) { return path.join(this.reposDir, owner, name + '.git'); }
  gitRepo(owner, name) { return new GitRepo(this.repoPath(owner, name)); }
  repoExists(owner, name) { return !!this.repos[owner + '/' + name]; }

  // --- users ---------------------------------------------------------------
  createUser(login, name, email) {
    if (!validLogin(login)) throw Object.assign(new Error('invalid login'), { status: 422 });
    if (this.users[login]) throw Object.assign(new Error('user already exists'), { status: 422 });
    const token = this.testMode
      ? 'forge_test_' + sha256hex('forge-test-token:' + login).slice(0, 32)
      : 'forge_' + crypto.randomBytes(24).toString('hex');
    const user = { login, name: name || login, email: email || login + '@forge.local', token, created_at: this.nowIso() };
    this.users[login] = user;
    this.save();
    return user;
  }
  userByToken(token) {
    if (!token) return null;
    for (const u of Object.values(this.users)) if (u.token === token) return u;
    return null;
  }
  publicUser(u) {
    return { login: u.login, name: u.name, email: u.email, type: 'User', created_at: u.created_at };
  }

  // --- repos ---------------------------------------------------------------
  createRepo(ownerLogin, opts) {
    opts = opts || {};
    const name = opts.name;
    if (!validRepoName(name)) throw Object.assign(new Error('invalid repository name'), { status: 422 });
    const full = ownerLogin + '/' + name;
    if (this.repos[full]) throw Object.assign(new Error('repository already exists'), { status: 422 });
    const defBranch = opts.default_branch || 'main';
    const repo = {
      id: this.counters.repoId++,
      name, full_name: full, owner: ownerLogin,
      description: opts.description || '',
      private: !!opts.private,
      default_branch: defBranch,
      created_at: this.nowIso(), updated_at: this.nowIso(),
      size: 0, fork: false,
    };
    this.repos[full] = repo;
    const gr = this.gitRepo(ownerLogin, name);
    gr.init();
    fs.writeFileSync(path.join(gr.root, 'HEAD'), 'ref: refs/heads/' + defBranch + '\n');
    this.issues[full] = [];
    this.pulls[full] = [];
    this.save();
    return repo;
  }
  getRepo(owner, name) { return this.repos[owner + '/' + name] || null; }
  deleteRepo(owner, name) {
    const full = owner + '/' + name;
    if (!this.repos[full]) return false;
    delete this.repos[full];
    delete this.issues[full];
    delete this.pulls[full];
    try { fs.rmSync(this.repoPath(owner, name), { recursive: true, force: true }); } catch (e) {}
    this.save();
    return true;
  }
  repoJson(r, baseUrl) {
    return {
      id: r.id, node_id: 'R_' + r.id, name: r.name, full_name: r.full_name,
      owner: { login: r.owner, type: 'User' },
      private: r.private, description: r.description,
      html_url: baseUrl + '/' + r.full_name,
      clone_url: baseUrl + '/' + r.full_name + '.git',
      git_url: baseUrl + '/' + r.full_name + '.git',
      ssh_url: 'git@forge.local:' + r.full_name + '.git',
      url: baseUrl + '/api/repos/' + r.full_name,
      default_branch: r.default_branch, created_at: r.created_at, updated_at: r.updated_at,
      size: r.size, fork: r.fork, open_issues_count: (this.issues[r.full_name] || []).filter((i) => i.state === 'open').length,
      has_issues: true, has_pull_requests: true, visibility: r.private ? 'private' : 'public',
    };
  }
  listUserRepos(login) {
    return Object.values(this.repos).filter((r) => r.owner === login)
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  // --- commits / contents ----------------------------------------------------
  commitFiles(owner, name, opts) {
    // opts: { branch, message, author:{name,email}, files: Map<path, Buffer|null>, timestamp }
    const repo = this.getRepo(owner, name);
    if (!repo) throw Object.assign(new Error('repository not found'), { status: 404 });
    const gr = this.gitRepo(owner, name);
    const branch = opts.branch || repo.default_branch;
    const ref = 'refs/heads/' + branch;
    const baseSha = gr.readRef(ref);
    let files = new Map();
    let parents = [];
    if (baseSha) {
      const c = gr.parseCommit(baseSha);
      files = gr.flattenTree(c.tree);
      parents = [baseSha];
    }
    for (const [p, content] of opts.files) {
      if (content === null) files.delete(p);
      else files.set(p, { mode: '100644', sha: gr.writeObject('blob', content) });
    }
    const treeSha = gr.buildTreeFromFiles(files);
    const author = opts.author || { name: owner, email: owner + '@forge.local' };
    const commitSha = gr.createCommit({
      tree: treeSha, parents, author, committer: author,
      message: opts.message || 'commit', timestamp: opts.timestamp != null ? opts.timestamp : this.nowTs(),
    });
    gr.writeRef(ref, commitSha);
    repo.updated_at = this.nowIso();
    this.save();
    return { sha: commitSha, tree: treeSha, branch };
  }
  readFileAt(owner, name, refName, filePath) {
    const repo = this.getRepo(owner, name);
    if (!repo) return null;
    const gr = this.gitRepo(owner, name);
    const sha = gr.resolveRef(refName || repo.default_branch);
    if (!sha) return null;
    const c = gr.parseCommit(sha);
    const files = gr.flattenTree(c.tree);
    const f = files.get(filePath);
    if (!f) return null;
    const obj = gr.readObject(f.sha);
    return { sha: f.sha, mode: f.mode, content: obj.data, commit: sha };
  }
  listTreeAt(owner, name, refName, dirPath) {
    const repo = this.getRepo(owner, name);
    if (!repo) return null;
    const gr = this.gitRepo(owner, name);
    const sha = gr.resolveRef(refName || repo.default_branch);
    if (!sha) return null;
    const c = gr.parseCommit(sha);
    const files = gr.flattenTree(c.tree);
    const out = [];
    const seen = new Set();
    for (const p of files.keys()) {
      const rel = dirPath ? (p.startsWith(dirPath + '/') ? p.slice(dirPath.length + 1) : null) : p;
      if (rel === null || rel === '') continue;
      const slash = rel.indexOf('/');
      if (slash === -1) {
        out.push({ type: 'file', name: rel, path: dirPath ? dirPath + '/' + rel : rel, sha: files.get(p).sha });
      } else {
        const d = rel.slice(0, slash);
        if (!seen.has(d)) {
          seen.add(d);
          out.push({ type: 'dir', name: d, path: dirPath ? dirPath + '/' + d : d, sha: null });
        }
      }
    }
    out.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1));
    return { commit: sha, entries: out };
  }
  listBranches(owner, name) {
    const repo = this.getRepo(owner, name);
    if (!repo) return null;
    const gr = this.gitRepo(owner, name);
    return gr.listRefs('refs/heads/').map((r) => ({
      name: r.ref.slice('refs/heads/'.length),
      commit: { sha: r.sha, url: '/api/repos/' + owner + '/' + name + '/commits/' + r.sha },
      protected: false,
    }));
  }
  listCommits(owner, name, refName, limit) {
    const repo = this.getRepo(owner, name);
    if (!repo) return null;
    const gr = this.gitRepo(owner, name);
    const sha = gr.resolveRef(refName || repo.default_branch);
    if (!sha) return [];
    return gr.listCommits(sha, limit || 30).map((c) => this.commitJson(owner, name, c));
  }
  getCommit(owner, name, sha) {
    const repo = this.getRepo(owner, name);
    if (!repo) return null;
    const gr = this.gitRepo(owner, name);
    if (!gr.hasObject(sha)) return null;
    let c;
    try { c = gr.parseCommit(sha); } catch (e) { return null; }
    return this.commitJson(owner, name, c);
  }
  commitJson(owner, name, c) {
    const parseIdent = (s) => {
      const m = String(s || '').match(/^(.*) <(.*)> (\d+) ([+-]\d{4})$/);
      return m ? { name: m[1], email: m[2], date: new Date(parseInt(m[3], 10) * 1000).toISOString() } : { name: '', email: '', date: '' };
    };
    return {
      sha: c.sha, node_id: 'C_' + c.sha.slice(0, 12),
      commit: {
        author: parseIdent(c.author), committer: parseIdent(c.committer),
        message: c.message, tree: { sha: c.tree },
      },
      author: null, committer: null,
      parents: c.parents.map((p) => ({ sha: p })),
      url: '/api/repos/' + owner + '/' + name + '/commits/' + c.sha,
      html_url: '/' + owner + '/' + name + '/commit/' + c.sha,
    };
  }
  createRef(owner, name, ref, sha) {
    const repo = this.getRepo(owner, name);
    if (!repo) throw Object.assign(new Error('repository not found'), { status: 404 });
    const gr = this.gitRepo(owner, name);
    if (!gr.hasObject(sha)) throw Object.assign(new Error('object not found: ' + sha), { status: 422 });
    if (gr.readRef(ref)) throw Object.assign(new Error('reference already exists'), { status: 422 });
    gr.writeRef(ref, sha);
    return { ref, object: { sha, type: 'commit', url: '/api/repos/' + owner + '/' + name + '/git/commits/' + sha } };
  }
  updateRef(owner, name, ref, sha, force) {
    const repo = this.getRepo(owner, name);
    if (!repo) throw Object.assign(new Error('repository not found'), { status: 404 });
    const gr = this.gitRepo(owner, name);
    if (!gr.hasObject(sha)) throw Object.assign(new Error('object not found: ' + sha), { status: 422 });
    const cur = gr.readRef(ref);
    if (!cur) throw Object.assign(new Error('reference not found'), { status: 404 });
    if (!force && !gr.isAncestor(cur, sha)) {
      throw Object.assign(new Error('update is not a fast forward'), { status: 422 });
    }
    gr.writeRef(ref, sha);
    return { ref, object: { sha, type: 'commit' } };
  }
}

// --- issues & pull requests (prototype methods, kept after the class) --------
function lineDiff(oldText, newText) {
  // tiny unified diff: common prefix/suffix, middle as -/+ lines
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const out = [];
  for (let i = pre; i < a.length - suf; i++) out.push('-' + a[i]);
  for (let i = pre; i < b.length - suf; i++) out.push('+' + b[i]);
  return out.join('\n');
}

Forge.prototype.nextIssueNumber = function (full) {
  const list = this.issues[full] || [];
  return list.reduce((m, i) => Math.max(m, i.number), 0) + 1;
};
Forge.prototype.nextPullNumber = function (full) {
  const list = this.pulls[full] || [];
  return list.reduce((m, p) => Math.max(m, p.number), 0) + 1;
};
Forge.prototype.createIssue = function (owner, name, user, opts) {
  const repo = this.getRepo(owner, name);
  if (!repo) throw Object.assign(new Error('repository not found'), { status: 404 });
  const full = owner + '/' + name;
  const n = this.nextIssueNumber(full);
  const issue = {
    id: this.counters.repoId * 100000 + n, number: n, title: opts.title || '',
    body: opts.body || '', state: 'open', user: { login: user.login },
    labels: opts.labels || [], assignees: [], comments: [],
    created_at: this.nowIso(), updated_at: this.nowIso(),
    html_url: '/' + full + '/issues/' + n,
    url: '/api/repos/' + full + '/issues/' + n,
  };
  (this.issues[full] = this.issues[full] || []).push(issue);
  this.save();
  return issue;
};
Forge.prototype.listIssues = function (owner, name, state) {
  const full = owner + '/' + name;
  if (!this.repos[full]) return null;
  let list = this.issues[full] || [];
  if (state && state !== 'all') list = list.filter((i) => i.state === state);
  return list.slice().sort((a, b) => b.number - a.number);
};
Forge.prototype.getIssue = function (owner, name, number) {
  const list = this.issues[owner + '/' + name] || [];
  return list.find((i) => i.number === number) || null;
};
Forge.prototype.updateIssue = function (owner, name, number, patch) {
  const issue = this.getIssue(owner, name, number);
  if (!issue) throw Object.assign(new Error('issue not found'), { status: 404 });
  if (typeof patch.title === 'string') issue.title = patch.title;
  if (typeof patch.body === 'string') issue.body = patch.body;
  if (patch.state === 'open' || patch.state === 'closed') issue.state = patch.state;
  if (Array.isArray(patch.labels)) issue.labels = patch.labels;
  issue.updated_at = this.nowIso();
  this.save();
  return issue;
};
Forge.prototype.addIssueComment = function (owner, name, number, user, body) {
  const issue = this.getIssue(owner, name, number);
  if (!issue) throw Object.assign(new Error('issue not found'), { status: 404 });
  const comment = {
    id: issue.id * 1000 + issue.comments.length + 1,
    body: body || '', user: { login: user.login },
    created_at: this.nowIso(), updated_at: this.nowIso(),
  };
  issue.comments.push(comment);
  issue.updated_at = this.nowIso();
  this.save();
  return comment;
};
Forge.prototype.issueJson = function (issue) {
  return {
    id: issue.id, number: issue.number, title: issue.title, body: issue.body,
    state: issue.state, user: issue.user, labels: issue.labels,
    assignees: issue.assignees, comments: issue.comments.length,
    created_at: issue.created_at, updated_at: issue.updated_at,
    html_url: issue.html_url, url: issue.url,
  };
};

Forge.prototype.createPull = function (owner, name, user, opts) {
  const repo = this.getRepo(owner, name);
  if (!repo) throw Object.assign(new Error('repository not found'), { status: 404 });
  const gr = this.gitRepo(owner, name);
  const base = opts.base || repo.default_branch;
  const head = opts.head;
  if (!head) throw Object.assign(new Error('head branch is required'), { status: 422 });
  const baseSha = gr.resolveRef(base);
  const headSha = gr.resolveRef(head);
  if (!baseSha) throw Object.assign(new Error('base branch not found: ' + base), { status: 422 });
  if (!headSha) throw Object.assign(new Error('head branch not found: ' + head), { status: 422 });
  const full = owner + '/' + name;
  const n = this.nextPullNumber(full);
  const pr = {
    id: this.counters.repoId * 100000 + 50000 + n, number: n,
    title: opts.title || '', body: opts.body || '', state: 'open',
    user: { login: user.login }, merged: false, merge_commit_sha: null,
    mergeable: true, mergeable_state: 'clean',
    head: { ref: head, sha: headSha, repo: { full_name: full } },
    base: { ref: base, sha: baseSha, repo: { full_name: full } },
    created_at: this.nowIso(), updated_at: this.nowIso(),
    html_url: '/' + full + '/pull/' + n,
    url: '/api/repos/' + full + '/pulls/' + n,
  };
  (this.pulls[full] = this.pulls[full] || []).push(pr);
  this.save();
  return pr;
};
Forge.prototype.listPulls = function (owner, name, state) {
  const full = owner + '/' + name;
  if (!this.repos[full]) return null;
  let list = this.pulls[full] || [];
  if (state && state !== 'all') list = list.filter((p) => p.state === state);
  return list.slice().sort((a, b) => b.number - a.number);
};
Forge.prototype.getPull = function (owner, name, number) {
  const list = this.pulls[owner + '/' + name] || [];
  return list.find((p) => p.number === number) || null;
};
Forge.prototype.updatePull = function (owner, name, number, patch) {
  const pr = this.getPull(owner, name, number);
  if (!pr) throw Object.assign(new Error('pull request not found'), { status: 404 });
  if (typeof patch.title === 'string') pr.title = patch.title;
  if (typeof patch.body === 'string') pr.body = patch.body;
  if (patch.state === 'open' || patch.state === 'closed') pr.state = patch.state;
  pr.updated_at = this.nowIso();
  this.save();
  return pr;
};
Forge.prototype.pullFiles = function (owner, name, number) {
  const pr = this.getPull(owner, name, number);
  if (!pr) return null;
  const gr = this.gitRepo(owner, name);
  const base = gr.parseCommit(pr.base.sha);
  const head = gr.parseCommit(pr.head.sha);
  const bf = gr.flattenTree(base.tree);
  const hf = gr.flattenTree(head.tree);
  const out = [];
  const paths = [...new Set([...bf.keys(), ...hf.keys()])].sort();
  for (const p of paths) {
    const b = bf.get(p), h = hf.get(p);
    if (b && h && b.sha === h.sha) continue;
    const status = !b ? 'added' : !h ? 'removed' : 'modified';
    const oldText = b ? gr.readObject(b.sha).data.toString('utf8') : '';
    const newText = h ? gr.readObject(h.sha).data.toString('utf8') : '';
    const additions = newText === '' ? 0 : newText.split('\n').length - (oldText === '' ? 0 : oldText.split('\n').length);
    out.push({
      sha: h ? h.sha : b.sha, filename: p, status,
      additions: status === 'removed' ? 0 : Math.max(0, additions),
      deletions: status === 'added' ? 0 : Math.max(0, -additions),
      patch: status === 'removed' ? lineDiff(oldText, '') : lineDiff(oldText, newText),
    });
  }
  return out;
};
Forge.prototype.pullCommits = function (owner, name, number) {
  const pr = this.getPull(owner, name, number);
  if (!pr) return null;
  const gr = this.gitRepo(owner, name);
  const baseReach = gr.reachableObjects([pr.base.sha]);
  const commits = gr.listCommits(pr.head.sha, 100).filter((c) => !baseReach.has(c.sha));
  return commits.map((c) => this.commitJson(owner, name, c));
};
Forge.prototype.mergePull = function (owner, name, number, user, opts) {
  const pr = this.getPull(owner, name, number);
  if (!pr) throw Object.assign(new Error('pull request not found'), { status: 404 });
  if (pr.state !== 'open') throw Object.assign(new Error('pull request is not open'), { status: 405 });
  if (pr.merged) throw Object.assign(new Error('pull request already merged'), { status: 405 });
  const gr = this.gitRepo(owner, name);
  const baseRef = 'refs/heads/' + pr.base.ref;
  const headRef = 'refs/heads/' + pr.head.ref;
  const baseSha = gr.readRef(baseRef);
  const headSha = gr.readRef(headRef);
  if (!baseSha || !headSha) throw Object.assign(new Error('branch head missing'), { status: 422 });
  const author = { name: user.login, email: user.login + '@forge.local' };
  let mergeSha;
  let method = 'merge';
  if (gr.isAncestor(baseSha, headSha)) {
    // fast-forward
    gr.writeRef(baseRef, headSha);
    mergeSha = headSha;
    method = 'fast-forward';
  } else {
    const mb = gr.mergeBase(baseSha, headSha);
    if (!mb) throw Object.assign(new Error('no merge base (unrelated histories)'), { status: 422 });
    const anc = gr.flattenTree(gr.parseCommit(mb).tree);
    const baseFiles = gr.flattenTree(gr.parseCommit(baseSha).tree);
    const headFiles = gr.flattenTree(gr.parseCommit(headSha).tree);
    const merged = new Map(baseFiles);
    const conflicts = [];
    const all = [...new Set([...anc.keys(), ...baseFiles.keys(), ...headFiles.keys()])].sort();
    for (const p of all) {
      const a = anc.get(p), b = baseFiles.get(p), h = headFiles.get(p);
      const same = (x, y) => (x && y && x.sha === y.sha) || (!x && !y);
      if (same(h, a)) { /* head unchanged: keep base */ }
      else if (same(b, a)) { if (h) merged.set(p, h); else merged.delete(p); }
      else if (!same(b, h)) { conflicts.push(p); if (h) merged.set(p, h); else merged.delete(p); }
    }
    const treeSha = gr.buildTreeFromFiles(merged);
    mergeSha = gr.createCommit({
      tree: treeSha, parents: [baseSha, headSha], author, committer: author,
      message: 'Merge pull request #' + number + ' from ' + pr.head.ref + '\n\n' + pr.title,
      timestamp: this.nowTs(),
    });
    gr.writeRef(baseRef, mergeSha);
    if (conflicts.length) pr.mergeable_state = 'dirty';
  }
  pr.merged = true;
  pr.merge_commit_sha = mergeSha;
  pr.state = 'closed';
  pr.updated_at = this.nowIso();
  const repo = this.getRepo(owner, name);
  if (repo) repo.updated_at = this.nowIso();
  this.save();
  return { merged: true, message: 'Pull Request successfully merged', sha: mergeSha, method, merge_commit_sha: mergeSha };
};
Forge.prototype.pullJson = function (pr) {
  return {
    id: pr.id, number: pr.number, title: pr.title, body: pr.body,
    state: pr.state, user: pr.user, merged: pr.merged,
    merge_commit_sha: pr.merge_commit_sha, mergeable: pr.mergeable,
    mergeable_state: pr.mergeable_state, head: pr.head, base: pr.base,
    created_at: pr.created_at, updated_at: pr.updated_at,
    html_url: pr.html_url, url: pr.url,
  };
};

// ---------------------------------------------------------------------------
// HTTP layer: auth, REST API, git smart HTTP, web UI
// ---------------------------------------------------------------------------

function authToken(req) {
  const h = req.headers.authorization || '';
  if (h.startsWith('token ')) return h.slice(6).trim();
  if (h.startsWith('Bearer ')) return h.slice(7).trim();
  if (h.startsWith('Basic ')) {
    const dec = Buffer.from(h.slice(6), 'base64').toString('utf8');
    const idx = dec.indexOf(':');
    return idx === -1 ? dec : dec.slice(idx + 1);
  }
  return null;
}
function requireAuth(req, res, forge) {
  const user = forge.userByToken(authToken(req));
  if (!user) { sendJson(res, 401, { message: 'Requires authentication', documentation_url: '/api' }); return null; }
  return user;
}
function checkRepoAccess(forge, owner, name, user) {
  const repo = forge.getRepo(owner, name);
  if (!repo) return { error: 404 };
  if (repo.private && (!user || user.login !== owner)) return { error: 404 };
  return { repo };
}

async function handleApi(req, res, forge, baseUrl) {
  const url = new URL(req.url, baseUrl);
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]
  const method = req.method;
  const q = url.searchParams;
  const api = parts.slice(1); // after 'api'
  try {
    // ---- meta -------------------------------------------------------------
    if (api.length === 0 && method === 'GET') {
      return sendJson(res, 200, { forge: 'forge', version: VERSION, api: 'github-compatible v3 subset', endpoints: ['users', 'repos', 'issues', 'pulls', 'git'] });
    }
    // ---- users ------------------------------------------------------------
    if (api[0] === 'users' && api.length === 2 && method === 'GET') {
      const u = forge.users[api[1]];
      if (!u) return sendJson(res, 404, { message: 'Not Found' });
      return sendJson(res, 200, forge.publicUser(u));
    }
    if (api[0] === 'users' && api.length === 1 && method === 'POST') {
      const body = await jsonBody(req);
      const u = forge.createUser(body.login, body.name, body.email);
      return sendJson(res, 201, Object.assign(forge.publicUser(u), { token: u.token }));
    }
    if (api[0] === 'user' && api.length === 1 && method === 'GET') {
      const user = requireAuth(req, res, forge);
      if (!user) return;
      return sendJson(res, 200, forge.publicUser(user));
    }
    if (api[0] === 'user' && api[1] === 'repos' && api.length === 2) {
      const user = requireAuth(req, res, forge);
      if (!user) return;
      if (method === 'GET') return sendJson(res, 200, forge.listUserRepos(user.login).map((r) => forge.repoJson(r, baseUrl)));
      if (method === 'POST') {
        const body = await jsonBody(req);
        const r = forge.createRepo(user.login, body);
        return sendJson(res, 201, forge.repoJson(r, baseUrl));
      }
      return sendJson(res, 405, { message: 'Method Not Allowed' });
    }
    if (api[0] === 'users' && api[2] === 'repos' && api.length === 3 && method === 'GET') {
      const list = forge.listUserRepos(api[1]).filter((r) => !r.private);
      return sendJson(res, 200, list.map((r) => forge.repoJson(r, baseUrl)));
    }
    // ---- repos ------------------------------------------------------------
    if (api[0] === 'repos' && api.length >= 3) {
      const owner = api[1], name = api[2];
      const rest = api.slice(3);
      const user = forge.userByToken(authToken(req));
      const acc = checkRepoAccess(forge, owner, name, user);
      if (acc.error) return sendJson(res, 404, { message: 'Not Found' });
      const repo = acc.repo;
      const full = owner + '/' + name;
      // repo itself
      if (rest.length === 0) {
        if (method === 'GET') return sendJson(res, 200, forge.repoJson(repo, baseUrl));
        if (method === 'PATCH') {
          if (!user || user.login !== owner) return sendJson(res, 403, { message: 'Forbidden' });
          const body = await jsonBody(req);
          if (typeof body.description === 'string') repo.description = body.description;
          if (typeof body.private === 'boolean') repo.private = body.private;
          if (typeof body.default_branch === 'string') repo.default_branch = body.default_branch;
          repo.updated_at = forge.nowIso();
          forge.save();
          return sendJson(res, 200, forge.repoJson(repo, baseUrl));
        }
        if (method === 'DELETE') {
          if (!user || user.login !== owner) return sendJson(res, 403, { message: 'Forbidden' });
          forge.deleteRepo(owner, name);
          return sendText(res, 204, '');
        }
        return sendJson(res, 405, { message: 'Method Not Allowed' });
      }
      // branches
      if (rest[0] === 'branches' && rest.length === 1 && method === 'GET') {
        return sendJson(res, 200, forge.listBranches(owner, name));
      }
      // commits
      if (rest[0] === 'commits') {
        if (rest.length === 1 && method === 'GET') {
          const list = forge.listCommits(owner, name, q.get('sha'), parseInt(q.get('per_page') || '30', 10));
          return sendJson(res, 200, list);
        }
        if (rest.length === 2 && method === 'GET') {
          const c = forge.getCommit(owner, name, rest[1]);
          if (!c) return sendJson(res, 404, { message: 'Not Found' });
          const gr = forge.gitRepo(owner, name);
          const commit = gr.parseCommit(rest[1]);
          const files = [...gr.flattenTree(commit.tree).keys()].sort();
          c.files = files.map((f) => ({ filename: f }));
          return sendJson(res, 200, c);
        }
      }
      // contents
      if (rest[0] === 'contents') {
        const filePath = decodeURIComponent(rest.slice(1).join('/'));
        const refName = q.get('ref') || repo.default_branch;
        if (method === 'GET') {
          if (!filePath) {
            const tree = forge.listTreeAt(owner, name, refName, '');
            if (!tree) return sendJson(res, 404, { message: 'Not Found' });
            return sendJson(res, 200, tree.entries.map((e) => ({
              type: e.type, name: e.name, path: e.path, sha: e.sha, size: 0,
              url: baseUrl + '/api/repos/' + full + '/contents/' + e.path + '?ref=' + encodeURIComponent(refName),
              html_url: baseUrl + '/' + full + '/blob/' + encodeURIComponent(refName) + '/' + e.path,
            })));
          }
          const f = forge.readFileAt(owner, name, refName, filePath);
          if (f) {
            return sendJson(res, 200, {
              type: 'file', name: path.posix.basename(filePath), path: filePath, sha: f.sha,
              size: f.content.length, content: b64encode(f.content), encoding: 'base64',
              url: baseUrl + '/api/repos/' + full + '/contents/' + filePath,
              html_url: baseUrl + '/' + full + '/blob/' + encodeURIComponent(refName) + '/' + filePath,
              download_url: baseUrl + '/api/repos/' + full + '/contents/' + filePath + '?ref=' + encodeURIComponent(refName),
            });
          }
          const tree = forge.listTreeAt(owner, name, refName, filePath);
          if (tree && tree.entries.length > 0) {
            return sendJson(res, 200, tree.entries.map((e) => ({
              type: e.type, name: e.name, path: e.path, sha: e.sha, size: 0,
              url: baseUrl + '/api/repos/' + full + '/contents/' + e.path + '?ref=' + encodeURIComponent(refName),
              html_url: baseUrl + '/' + full + '/blob/' + encodeURIComponent(refName) + '/' + e.path,
            })));
          }
          return sendJson(res, 404, { message: 'Not Found' });
        }
        if (method === 'PUT' || method === 'DELETE') {
          const me = requireAuth(req, res, forge);
          if (!me) return;
          const body = await jsonBody(req);
          const branch = body.branch || repo.default_branch;
          const author = { name: me.login, email: me.email };
          if (method === 'PUT') {
            if (typeof body.content !== 'string') return sendJson(res, 422, { message: 'content (base64) is required' });
            const existing = forge.readFileAt(owner, name, branch, filePath);
            if (body.sha && existing && body.sha !== existing.sha) {
              return sendJson(res, 409, { message: 'sha does not match the current file' });
            }
            const files = new Map([[filePath, b64decode(body.content)]]);
            const c = forge.commitFiles(owner, name, {
              branch, message: body.message || (existing ? 'Update ' + filePath : 'Create ' + filePath),
              author, files, timestamp: forge.nowTs(),
            });
            const f = forge.readFileAt(owner, name, branch, filePath);
            return sendJson(res, existing ? 200 : 201, {
              content: { type: 'file', name: path.posix.basename(filePath), path: filePath, sha: f.sha, size: f.content.length, content: body.content, encoding: 'base64' },
              commit: { sha: c.sha, message: body.message || 'commit' },
            });
          }
          // DELETE
          const existing = forge.readFileAt(owner, name, branch, filePath);
          if (!existing) return sendJson(res, 404, { message: 'Not Found' });
          if (body.sha && body.sha !== existing.sha) return sendJson(res, 409, { message: 'sha does not match the current file' });
          const files = new Map([[filePath, null]]);
          const c = forge.commitFiles(owner, name, {
            branch, message: body.message || 'Delete ' + filePath, author, files, timestamp: forge.nowTs(),
          });
          return sendJson(res, 200, { commit: { sha: c.sha, message: body.message || 'Delete ' + filePath } });
        }
        return sendJson(res, 405, { message: 'Method Not Allowed' });
      }
      // git refs
      if (rest[0] === 'git' && rest[1] === 'refs') {
        const refPath = rest.slice(2).join('/');
        if (method === 'GET' && refPath === '') {
          const gr = forge.gitRepo(owner, name);
          return sendJson(res, 200, gr.listRefs('refs/').filter((r) => r.ref !== 'HEAD').map((r) => ({
            ref: r.ref, node_id: 'R_' + r.sha.slice(0, 12),
            url: baseUrl + '/api/repos/' + full + '/git/refs/' + r.ref,
            object: { sha: r.sha, type: 'commit', url: baseUrl + '/api/repos/' + full + '/git/commits/' + r.sha },
          })));
        }
        if (method === 'GET' && refPath) {
          const gr = forge.gitRepo(owner, name);
          const sha = gr.readRef(refPath);
          if (!sha) return sendJson(res, 404, { message: 'Not Found' });
          return sendJson(res, 200, { ref: refPath, object: { sha, type: 'commit' } });
        }
        if (method === 'POST' && refPath === '') {
          const me = requireAuth(req, res, forge);
          if (!me) return;
          const body = await jsonBody(req);
          const r = forge.createRef(owner, name, body.ref, body.sha);
          return sendJson(res, 201, r);
        }
        if (method === 'PATCH' && refPath) {
          const me = requireAuth(req, res, forge);
          if (!me) return;
          const body = await jsonBody(req);
          const r = forge.updateRef(owner, name, refPath, body.sha, !!body.force);
          return sendJson(res, 200, r);
        }
        return sendJson(res, 405, { message: 'Method Not Allowed' });
      }
      // issues
      if (rest[0] === 'issues') {
        if (rest.length === 1) {
          if (method === 'GET') {
            const list = forge.listIssues(owner, name, q.get('state') || 'open');
            if (list === null) return sendJson(res, 404, { message: 'Not Found' });
            return sendJson(res, 200, list.map((i) => forge.issueJson(i)));
          }
          if (method === 'POST') {
            const me = requireAuth(req, res, forge);
            if (!me) return;
            const body = await jsonBody(req);
            if (!body.title) return sendJson(res, 422, { message: 'title is required' });
            const issue = forge.createIssue(owner, name, me, body);
            return sendJson(res, 201, forge.issueJson(issue));
          }
        }
        const num = parseInt(rest[1], 10);
        if (rest.length === 2 && !isNaN(num)) {
          if (method === 'GET') {
            const issue = forge.getIssue(owner, name, num);
            if (!issue) return sendJson(res, 404, { message: 'Not Found' });
            const j = forge.issueJson(issue);
            j.comments_list = issue.comments;
            return sendJson(res, 200, j);
          }
          if (method === 'PATCH') {
            const me = requireAuth(req, res, forge);
            if (!me) return;
            const body = await jsonBody(req);
            const issue = forge.updateIssue(owner, name, num, body);
            return sendJson(res, 200, forge.issueJson(issue));
          }
        }
        if (rest.length === 3 && rest[2] === 'comments' && !isNaN(num)) {
          if (method === 'GET') {
            const issue = forge.getIssue(owner, name, num);
            if (!issue) return sendJson(res, 404, { message: 'Not Found' });
            return sendJson(res, 200, issue.comments);
          }
          if (method === 'POST') {
            const me = requireAuth(req, res, forge);
            if (!me) return;
            const body = await jsonBody(req);
            if (!body.body) return sendJson(res, 422, { message: 'body is required' });
            const c = forge.addIssueComment(owner, name, num, me, body.body);
            return sendJson(res, 201, c);
          }
        }
        return sendJson(res, 404, { message: 'Not Found' });
      }
      // pulls
      if (rest[0] === 'pulls') {
        if (rest.length === 1) {
          if (method === 'GET') {
            const list = forge.listPulls(owner, name, q.get('state') || 'open');
            if (list === null) return sendJson(res, 404, { message: 'Not Found' });
            return sendJson(res, 200, list.map((p) => forge.pullJson(p)));
          }
          if (method === 'POST') {
            const me = requireAuth(req, res, forge);
            if (!me) return;
            const body = await jsonBody(req);
            const pr = forge.createPull(owner, name, me, body);
            return sendJson(res, 201, forge.pullJson(pr));
          }
        }
        const num = parseInt(rest[1], 10);
        if (!isNaN(num) && rest.length === 2) {
          if (method === 'GET') {
            const pr = forge.getPull(owner, name, num);
            if (!pr) return sendJson(res, 404, { message: 'Not Found' });
            return sendJson(res, 200, forge.pullJson(pr));
          }
          if (method === 'PATCH') {
            const me = requireAuth(req, res, forge);
            if (!me) return;
            const body = await jsonBody(req);
            const pr = forge.updatePull(owner, name, num, body);
            return sendJson(res, 200, forge.pullJson(pr));
          }
        }
        if (!isNaN(num) && rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          const files = forge.pullFiles(owner, name, num);
          if (files === null) return sendJson(res, 404, { message: 'Not Found' });
          return sendJson(res, 200, files);
        }
        if (!isNaN(num) && rest.length === 3 && rest[2] === 'commits' && method === 'GET') {
          const commits = forge.pullCommits(owner, name, num);
          if (commits === null) return sendJson(res, 404, { message: 'Not Found' });
          return sendJson(res, 200, commits);
        }
        if (!isNaN(num) && rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          const me = requireAuth(req, res, forge);
          if (!me) return;
          if (user.login !== owner) return sendJson(res, 403, { message: 'Only the repository owner can merge' });
          const body = await jsonBody(req);
          const r = forge.mergePull(owner, name, num, me, body);
          return sendJson(res, 200, r);
        }
        return sendJson(res, 404, { message: 'Not Found' });
      }
      return sendJson(res, 404, { message: 'Not Found' });
    }
    return sendJson(res, 404, { message: 'Not Found' });
  } catch (e) {
    if (e && e.status) return sendJson(res, e.status, { message: e.message });
    console.error(e);
    return sendJson(res, 500, { message: 'Internal Server Error' });
  }
}

async function handleGitHttp(req, res, forge) {
  const url = new URL(req.url, 'http://x');
  const m = url.pathname.match(/^\/([^\/]+)\/([^\/]+?)(?:\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/);
  if (!m) return sendText(res, 404, 'Not Found');
  const owner = decodeURIComponent(m[1]);
  const name = decodeURIComponent(m[2]);
  const action = m[3];
  const repo = forge.getRepo(owner, name);
  if (!repo) return sendText(res, 404, 'Not Found');
  const gr = forge.gitRepo(owner, name);
  try {
    if (action === 'info/refs' && req.method === 'GET') {
      const service = url.searchParams.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        return sendText(res, 400, 'unknown service');
      }
      const body = advertiseRefs(gr, service);
      const type = service === 'git-upload-pack'
        ? 'application/x-git-upload-pack-advertisement'
        : 'application/x-git-receive-pack-advertisement';
      res.writeHead(200, { 'content-type': type, 'content-length': body.length });
      return res.end(body);
    }
    if (action === 'git-upload-pack' && req.method === 'POST') {
      const body = await readBody(req);
      const out = handleUploadPack(gr, body);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': out.length });
      return res.end(out);
    }
    if (action === 'git-receive-pack' && req.method === 'POST') {
      const body = await readBody(req);
      const out = handleReceivePack(gr, body);
      res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': out.length });
      return res.end(out);
    }
    return sendText(res, 405, 'Method Not Allowed');
  } catch (e) {
    console.error(e);
    return sendText(res, 500, 'Internal Server Error: ' + e.message);
  }
}

// ---------------------------------------------------------------------------
// web UI (server-rendered HTML)
// ---------------------------------------------------------------------------

function mdLite(src) {
  // tiny markdown renderer: headings, bold, italic, code, links, lists, fences
  const lines = String(src || '').split('\n');
  let html = '';
  let inCode = false, inList = false;
  const inline = (s) => escHtml(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      html += inCode ? '</code></pre>' : '<pre><code>';
      inCode = !inCode;
      continue;
    }
    if (inCode) { html += escHtml(line) + '\n'; continue; }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      if (inList) { html += '</ul>'; inList = false; }
      html += '<h' + h[1].length + '>' + inline(h[2]) + '</h' + h[1].length + '>';
      continue;
    }
    const li = line.match(/^[-*]\s+(.*)$/);
    if (li) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += '<li>' + inline(li[1]) + '</li>';
      continue;
    }
    if (inList) { html += '</ul>'; inList = false; }
    if (line.trim() === '') continue;
    html += '<p>' + inline(line) + '</p>';
  }
  if (inList) html += '</ul>';
  if (inCode) html += '</code></pre>';
  return html;
}

function layout(title, body, baseUrl) {
  return '<!doctype html><html><head><meta charset="utf-8"><title>' + escHtml(title) + ' · forge</title>'
    + '<style>body{font-family:system-ui,sans-serif;max-width:880px;margin:0 auto;padding:24px;color:#1f2328}'
    + 'a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}'
    + 'header{border-bottom:1px solid #d0d7de;padding-bottom:12px;margin-bottom:20px}'
    + 'code,pre{background:#f6f8fa;border-radius:6px}pre{padding:12px;overflow:auto}'
    + 'code{padding:2px 4px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d0d7de;padding:6px 10px;text-align:left}'
    + '.muted{color:#656d76}.badge{display:inline-block;background:#ddf4ff;color:#0969da;border-radius:10px;padding:1px 8px;font-size:12px}'
    + 'input,textarea{font:inherit;padding:6px;border:1px solid #d0d7de;border-radius:6px;width:100%}'
    + 'button{font:inherit;padding:6px 14px;background:#1f883d;color:#fff;border:0;border-radius:6px;cursor:pointer}</style></head>'
    + '<body><header><a href="/"><strong>forge</strong></a> <span class="muted">a GitHub-compatible git forge</span></header>'
    + body + '<footer class="muted" style="margin-top:40px;border-top:1px solid #d0d7de;padding-top:12px">forge ' + VERSION
    + ' · git smart HTTP + GitHub-compatible REST API · <a href="/api">/api</a></footer></body></html>';
}

function handleWeb(req, res, forge, baseUrl) {
  const url = new URL(req.url, baseUrl);
  const parts = url.pathname.split('/').filter(Boolean).map((p) => decodeURIComponent(p));
  const user = forge.userByToken(authToken(req));
  try {
    // home: repo list
    if (parts.length === 0) {
      const repos = Object.values(forge.repos).filter((r) => !r.private).sort((a, b) => a.full_name.localeCompare(b.full_name));
      let body = '<h1>Repositories</h1>';
      if (!repos.length) body += '<p class="muted">No public repositories yet. Create one with the API:</p><pre>curl -X POST ' + escHtml(baseUrl) + '/api/user/repos -H "Authorization: token &lt;token&gt;" -d \'{"name":"hello"}\'</pre>';
      else {
        body += '<table><tr><th>Repository</th><th>Description</th><th>Issues</th></tr>';
        for (const r of repos) {
          const open = (forge.issues[r.full_name] || []).filter((i) => i.state === 'open').length;
          body += '<tr><td><a href="/' + escHtml(r.full_name) + '">' + escHtml(r.full_name) + '</a></td><td>' + escHtml(r.description) + '</td><td>' + open + ' open</td></tr>';
        }
        body += '</table>';
      }
      return sendHtml(res, 200, layout('Repositories', body, baseUrl));
    }
    // repo pages
    if (parts.length >= 2) {
      const owner = parts[0], name = parts[1];
      const acc = checkRepoAccess(forge, owner, name, user);
      if (acc.error) return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>Repository not found.</p>', baseUrl));
      const repo = acc.repo;
      const full = owner + '/' + name;
      const sub = parts.slice(2);
      const gr = forge.gitRepo(owner, name);
      const headSha = gr.readRef(gr.headRef());
      // repo root / tree / blob
      if (sub.length === 0 || sub[0] === 'tree' || sub[0] === 'blob') {
        let branch = repo.default_branch, dirPath = '';
        if (sub[0] === 'tree' || sub[0] === 'blob') {
          branch = sub[1] || repo.default_branch;
          dirPath = sub.slice(2).join('/');
        }
        const isBlob = sub[0] === 'blob';
        let body = '<h1><a href="/' + escHtml(owner) + '">' + escHtml(owner) + '</a> / ' + escHtml(name) + '</h1>'
          + '<p class="muted">' + escHtml(repo.description || '') + '</p>'
          + '<p><span class="badge">' + escHtml(branch) + '</span> '
          + '<a href="/' + escHtml(full) + '/commits/' + escHtml(branch) + '">commits</a> · '
          + '<a href="/' + escHtml(full) + '/issues">issues</a> · '
          + '<a href="/' + escHtml(full) + '/pulls">pull requests</a></p>'
          + '<p><code>git clone ' + escHtml(baseUrl) + '/' + escHtml(full) + '.git</code></p>';
        if (isBlob) {
          const f = forge.readFileAt(owner, name, branch, dirPath);
          if (!f) return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>File not found.</p>', baseUrl));
          body += '<h2>' + escHtml(dirPath) + '</h2><pre>' + escHtml(f.content.toString('utf8')) + '</pre>';
        } else {
          const tree = forge.listTreeAt(owner, name, branch, dirPath);
          if (!tree) return sendHtml(res, 404, layout('Empty repository', '<h1>' + escHtml(full) + '</h1><p class="muted">This repository is empty. Push a commit to get started.</p><pre>git clone ' + escHtml(baseUrl) + '/' + escHtml(full) + '.git</pre>', baseUrl));
          if (dirPath) body += '<p><a href="/' + escHtml(full) + '/tree/' + escHtml(branch) + '">..</a></p>';
          body += '<table><tr><th>Name</th><th>Type</th></tr>';
          for (const e of tree.entries) {
            const href = e.type === 'dir'
              ? '/' + escHtml(full) + '/tree/' + escHtml(branch) + '/' + escHtml(e.path)
              : '/' + escHtml(full) + '/blob/' + escHtml(branch) + '/' + escHtml(e.path);
            body += '<tr><td><a href="' + href + '">' + escHtml(e.name) + '</a></td><td>' + e.type + '</td></tr>';
          }
          body += '</table>';
          if (!dirPath) {
            const readme = forge.readFileAt(owner, name, branch, 'README.md') || forge.readFileAt(owner, name, branch, 'readme.md');
            if (readme) body += '<hr><div>' + mdLite(readme.content.toString('utf8')) + '</div>';
          }
        }
        return sendHtml(res, 200, layout(full, body, baseUrl));
      }
      // commits
      if (sub[0] === 'commits') {
        const branch = sub[1] || repo.default_branch;
        const list = forge.listCommits(owner, name, branch, 30);
        let body = '<h1>Commits on ' + escHtml(branch) + ' — ' + escHtml(full) + '</h1>';
        if (!list.length) body += '<p class="muted">No commits yet.</p>';
        else {
          body += '<table><tr><th>Commit</th><th>Message</th><th>Author</th></tr>';
          for (const c of list) {
            body += '<tr><td><a href="/' + escHtml(full) + '/commit/' + c.sha + '">' + c.sha.slice(0, 7) + '</a></td><td>' + escHtml(c.commit.message.split('\n')[0]) + '</td><td>' + escHtml(c.commit.author.name) + '</td></tr>';
          }
          body += '</table>';
        }
        return sendHtml(res, 200, layout('Commits · ' + full, body, baseUrl));
      }
      // single commit
      if (sub[0] === 'commit' && sub[1]) {
        const c = forge.getCommit(owner, name, sub[1]);
        if (!c) return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>Commit not found.</p>', baseUrl));
        let body = '<h1>Commit ' + c.sha.slice(0, 12) + '</h1><p>' + escHtml(c.commit.author.name) + ' · ' + escHtml(c.commit.author.date) + '</p><pre>' + escHtml(c.commit.message) + '</pre>';
        body += '<h2>Files</h2><ul>';
        for (const f of c.files || []) body += '<li>' + escHtml(f.filename) + '</li>';
        body += '</ul>';
        return sendHtml(res, 200, layout('Commit · ' + full, body, baseUrl));
      }
      // issues
      if (sub[0] === 'issues') {
        if (sub.length === 1) {
          const list = forge.listIssues(owner, name, 'all') || [];
          let body = '<h1>Issues — ' + escHtml(full) + '</h1>';
          if (!list.length) body += '<p class="muted">No issues.</p>';
          else {
            body += '<table><tr><th>#</th><th>Title</th><th>State</th><th>By</th></tr>';
            for (const i of list) body += '<tr><td>' + i.number + '</td><td><a href="/' + escHtml(full) + '/issues/' + i.number + '">' + escHtml(i.title) + '</a></td><td>' + i.state + '</td><td>' + escHtml(i.user.login) + '</td></tr>';
            body += '</table>';
          }
          return sendHtml(res, 200, layout('Issues · ' + full, body, baseUrl));
        }
        const num = parseInt(sub[1], 10);
        const issue = forge.getIssue(owner, name, num);
        if (!issue) return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>Issue not found.</p>', baseUrl));
        let body = '<h1>#' + issue.number + ' ' + escHtml(issue.title) + ' <span class="badge">' + issue.state + '</span></h1>'
          + '<p class="muted">opened by ' + escHtml(issue.user.login) + ' · ' + escHtml(issue.created_at) + '</p>'
          + '<div>' + mdLite(issue.body) + '</div><hr><h2>Comments (' + issue.comments.length + ')</h2>';
        for (const c of issue.comments) body += '<p><strong>' + escHtml(c.user.login) + '</strong> <span class="muted">' + escHtml(c.created_at) + '</span></p><div>' + mdLite(c.body) + '</div>';
        return sendHtml(res, 200, layout(issue.title + ' · ' + full, body, baseUrl));
      }
      // pulls
      if (sub[0] === 'pulls') {
        if (sub.length === 1) {
          const list = forge.listPulls(owner, name, 'all') || [];
          let body = '<h1>Pull requests — ' + escHtml(full) + '</h1>';
          if (!list.length) body += '<p class="muted">No pull requests.</p>';
          else {
            body += '<table><tr><th>#</th><th>Title</th><th>State</th><th>By</th><th>Branch</th></tr>';
            for (const p of list) body += '<tr><td>' + p.number + '</td><td><a href="/' + escHtml(full) + '/pulls/' + p.number + '">' + escHtml(p.title) + '</a></td><td>' + (p.merged ? 'merged' : p.state) + '</td><td>' + escHtml(p.user.login) + '</td><td>' + escHtml(p.head.ref) + ' → ' + escHtml(p.base.ref) + '</td></tr>';
            body += '</table>';
          }
          return sendHtml(res, 200, layout('Pull requests · ' + full, body, baseUrl));
        }
        const num = parseInt(sub[1], 10);
        const pr = forge.getPull(owner, name, num);
        if (!pr) return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>Pull request not found.</p>', baseUrl));
        const files = forge.pullFiles(owner, name, num) || [];
        let body = '<h1>#' + pr.number + ' ' + escHtml(pr.title) + ' <span class="badge">' + (pr.merged ? 'merged' : pr.state) + '</span></h1>'
          + '<p class="muted">' + escHtml(pr.head.ref) + ' → ' + escHtml(pr.base.ref) + ' · by ' + escHtml(pr.user.login) + '</p>'
          + '<div>' + mdLite(pr.body) + '</div><hr><h2>Files changed (' + files.length + ')</h2>';
        for (const f of files) body += '<p><strong>' + escHtml(f.filename) + '</strong> <span class="muted">' + f.status + '</span></p><pre>' + escHtml(f.patch || '') + '</pre>';
        return sendHtml(res, 200, layout(pr.title + ' · ' + full, body, baseUrl));
      }
      // fall back to repo root
      return sendHtml(res, 302, '');
    }
    return sendHtml(res, 404, layout('Not found', '<h1>404</h1><p>Page not found.</p>', baseUrl));
  } catch (e) {
    console.error(e);
    return sendHtml(res, 500, layout('Error', '<h1>500</h1><p>' + escHtml(e.message) + '</p>', baseUrl));
  }
}

// ---------------------------------------------------------------------------
// server + entrypoint
// ---------------------------------------------------------------------------

function createServer(forge) {
  const server = http.createServer(async (req, res) => {
    const host = req.headers.host || '127.0.0.1';
    const baseUrl = 'http://' + host;
    const pathname = new URL(req.url, baseUrl).pathname;
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      await handleApi(req, res, forge, baseUrl);
    } else if (/^\/[^\/]+\/[^\/]+?(\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/.test(pathname)) {
      await handleGitHttp(req, res, forge);
    } else {
      handleWeb(req, res, forge, baseUrl);
    }
  });
  return server;
}

function parseArgs(argv) {
  const out = { serve: false, port: null, data: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--serve') out.serve = true;
    else if (argv[i] === '--port' && argv[i + 1]) out.port = parseInt(argv[++i], 10);
    else if (argv[i] === '--data' && argv[i + 1]) out.data = argv[++i];
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.serve) {
    const dataDir = args.data || process.env.FORGE_DATA_DIR || path.join(process.cwd(), 'data');
    const port = args.port || parseInt(process.env.FORGE_PORT || '3000', 10);
    const host = process.env.FORGE_HOST || '127.0.0.1';
    const forge = new Forge(dataDir, {});
    const server = createServer(forge);
    server.listen(port, host, () => {
      console.log('forge ' + VERSION + ' listening on http://' + host + ':' + port);
      console.log('data dir: ' + dataDir);
      console.log('API: ' + 'http://' + host + ':' + port + '/api');
      console.log('git: git clone http://' + host + ':' + port + '/<owner>/<repo>.git');
    });
    return;
  }
  await runSelfTest();
}

// ---------------------------------------------------------------------------
// deterministic end-to-end self-test (default run)
// ---------------------------------------------------------------------------

function makeCommitIn(tempRepo, parentSha, files, message) {
  let map = new Map();
  if (parentSha) {
    const c = tempRepo.parseCommit(parentSha);
    map = tempRepo.flattenTree(c.tree);
  }
  for (const [p, content] of Object.entries(files)) {
    map.set(p, { mode: '100644', sha: tempRepo.writeObject('blob', Buffer.from(content, 'utf8')) });
  }
  const tree = tempRepo.buildTreeFromFiles(map);
  const who = { name: 'alice', email: 'alice@forge.local' };
  return tempRepo.createCommit({
    tree, parents: parentSha ? [parentSha] : [], author: who, committer: who,
    message, timestamp: FIXED_TS,
  });
}

async function runSelfTest() {
  console.log('forge ' + VERSION + ' — self-test');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'forge-test-'));
  const forge = new Forge(dir, { testMode: true, now: () => FIXED_TS * 1000 });
  const server = createServer(forge);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok });
    console.log((ok ? 'ok ' : 'FAIL ') + name + ' — ' + detail);
  };
  const api = async (method, p, token, body) => {
    const headers = { 'content-type': 'application/json' };
    if (token) headers.authorization = 'token ' + token;
    const r = await fetch(base + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let j = null;
    try { j = JSON.parse(text); } catch (e) { /* not json */ }
    return { status: r.status, json: j, text };
  };
  const raw = async (method, p, body, ctype) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': ctype || 'application/octet-stream' }, body });
    return { status: r.status, buf: Buffer.from(await r.arrayBuffer()) };
  };
  try {
    // 1-3: users + repo
    let r = await api('POST', '/api/users', null, { login: 'alice', name: 'Alice', email: 'alice@forge.local' });
    check('create-user', r.status === 201 && r.json && r.json.login === 'alice', 'POST /api/users -> 201, login=alice');
    const aliceToken = r.json && r.json.token;
    check('user-token', typeof aliceToken === 'string' && aliceToken.startsWith('forge_test_'), 'deterministic test token issued');
    r = await api('GET', '/api/user', aliceToken);
    check('get-user', r.status === 200 && r.json.login === 'alice', 'GET /api/user -> alice');
    r = await api('POST', '/api/user/repos', aliceToken, { name: 'hello', description: 'Hello world repo' });
    check('create-repo', r.status === 201 && r.json.full_name === 'alice/hello' && r.json.default_branch === 'main', 'POST /api/user/repos -> alice/hello, branch main');
    r = await api('GET', '/api/repos/alice/hello', null);
    check('get-repo', r.status === 200 && r.json.description === 'Hello world repo', 'GET /api/repos/alice/hello -> 200');

    // 4-6: push the first commit over the real git protocol, then clone it back
    const tmp = new GitRepo(path.join(dir, 'tmp-client'));
    tmp.init();
    const readme = '# hello\n\nHello world.\n';
    const mainJs = "console.log('hello');\n";
    const c1 = makeCommitIn(tmp, null, { 'README.md': readme, 'src/main.js': mainJs }, 'Initial commit');
    const pack1 = writePack(tmp, tmp.reachableObjects([c1]));
    const push1 = await raw('POST', '/alice/hello.git/git-receive-pack',
      buildReceivePackRequest([{ oldSha: ZERO_SHA, newSha: c1, ref: 'refs/heads/main' }], pack1),
      'application/x-git-receive-pack-request');
    const pushRes1 = parseReceivePackResponse(push1.buf);
    check('git-push-initial', push1.status === 200 && pushRes1.unpack === 'ok' && pushRes1.refs[0] && pushRes1.refs[0].ok, 'receive-pack: unpack ok, refs/heads/main created');
    r = await api('GET', '/api/repos/alice/hello/contents/README.md?ref=main', null);
    check('contents-readme', r.status === 200 && b64decode(r.json.content).toString('utf8') === readme, 'contents API returns the pushed README.md');
    const up = await raw('POST', '/alice/hello.git/git-upload-pack', buildUploadPackRequest([c1], []), 'application/x-git-upload-pack-request');
    const packBack = parseUploadPackResponse(up.buf);
    const objs = parsePack(packBack);
    const blob = objs.find((o) => o.type === 'blob' && o.data.toString('utf8') === readme);
    check('git-clone-pack', up.status === 200 && objs.length === 5 && !!blob, 'upload-pack: pack of 5 objects (commit+2 trees+2 blobs), README blob intact');

    // 7-9: contents API commit, commit list
    r = await api('PUT', '/api/repos/alice/hello/contents/docs/guide.md', aliceToken,
      { message: 'Add guide', content: b64encode(Buffer.from('# Guide\n\nHow to use hello.\n')), branch: 'main' });
    check('contents-put', r.status === 201 && r.json.commit && isSha(r.json.commit.sha), 'PUT contents docs/guide.md -> 201, new commit');
    const c2 = r.json.commit.sha;
    r = await api('GET', '/api/repos/alice/hello/commits?per_page=10', null);
    check('list-commits', r.status === 200 && r.json.length === 2 && r.json[0].commit.message === 'Add guide', 'GET commits -> 2 commits, newest first');

    // 10-12: branch + push to it + branches list
    r = await api('POST', '/api/repos/alice/hello/git/refs', aliceToken, { ref: 'refs/heads/feature', sha: c2 });
    check('create-branch', r.status === 201 && r.json.ref === 'refs/heads/feature', 'POST git/refs -> feature branch created');
    // fetch c2 into the local tmp repo first (a real git fetch over the protocol)
    const fetchC2 = await raw('POST', '/alice/hello.git/git-upload-pack', buildUploadPackRequest([c2], []), 'application/x-git-upload-pack-request');
    const fetchPack = parseUploadPackResponse(fetchC2.buf);
    for (const o of parsePack(fetchPack)) tmp.writeRawObject(o.sha, o.type, o.data);
    check('git-fetch', fetchC2.status === 200 && tmp.hasObject(c2), 'upload-pack fetch: c2 objects now in local repo');
    const c3 = makeCommitIn(tmp, c2, { 'src/feature.js': "console.log('feature');\n" }, 'Add feature');
    // send all objects reachable from c3 (the server tolerates ones it has)
    const pack2Objs = [...tmp.reachableObjects([c3])];
    const pack2b = writePack(tmp, pack2Objs);
    const push2 = await raw('POST', '/alice/hello.git/git-receive-pack',
      buildReceivePackRequest([{ oldSha: c2, newSha: c3, ref: 'refs/heads/feature' }], pack2b),
      'application/x-git-receive-pack-request');
    const pushRes2 = parseReceivePackResponse(push2.buf);
    check('git-push-feature', push2.status === 200 && pushRes2.unpack === 'ok' && pushRes2.refs[0] && pushRes2.refs[0].ok, 'receive-pack: feature branch updated to new commit');
    r = await api('GET', '/api/repos/alice/hello/branches', null);
    check('list-branches', r.status === 200 && r.json.length === 2 && r.json.map((b) => b.name).sort().join(',') === 'feature,main', 'GET branches -> feature, main');

    // 13-15: issues
    r = await api('POST', '/api/repos/alice/hello/issues', aliceToken, { title: 'Bug: hello crashes', body: 'It crashes on startup.' });
    check('create-issue', r.status === 201 && r.json.number === 1 && r.json.state === 'open', 'POST issues -> #1 open');
    r = await api('POST', '/api/repos/alice/hello/issues/1/comments', aliceToken, { body: 'Reproduced locally.' });
    check('issue-comment', r.status === 201 && r.json.body === 'Reproduced locally.', 'POST issue comment -> 201');
    r = await api('PATCH', '/api/repos/alice/hello/issues/1', aliceToken, { state: 'closed' });
    check('close-issue', r.status === 200 && r.json.state === 'closed', 'PATCH issue -> closed');

    // 16-20: pull request + merge
    r = await api('POST', '/api/repos/alice/hello/pulls', aliceToken, { title: 'Add feature', body: 'Adds src/feature.js', head: 'feature', base: 'main' });
    check('create-pr', r.status === 201 && r.json.number === 1 && r.json.state === 'open', 'POST pulls -> #1 open, feature -> main');
    r = await api('GET', '/api/repos/alice/hello/pulls/1/files', null);
    check('pr-files', r.status === 200 && r.json.length === 1 && r.json[0].filename === 'src/feature.js' && r.json[0].status === 'added', 'GET pull files -> src/feature.js added');
    r = await api('GET', '/api/repos/alice/hello/pulls/1/commits', null);
    check('pr-commits', r.status === 200 && r.json.length === 1 && r.json[0].commit.message === 'Add feature', 'GET pull commits -> 1 commit');
    r = await api('PUT', '/api/repos/alice/hello/pulls/1/merge', aliceToken, { merge_method: 'merge' });
    check('merge-pr', r.status === 200 && r.json.merged === true && isSha(r.json.merge_commit_sha), 'PUT merge -> merged, merge commit sha');
    const mergeSha = r.json.merge_commit_sha;
    r = await api('GET', '/api/repos/alice/hello/contents/src/feature.js?ref=main', null);
    check('merged-content', r.status === 200 && b64decode(r.json.content).toString('utf8') === "console.log('feature');\n", 'merged file visible on main after merge');

    // 21-25: refs, web UI, delete, second user
    r = await api('GET', '/api/repos/alice/hello/git/refs/refs/heads/main', null);
    check('get-ref', r.status === 200 && r.json.object.sha === mergeSha, 'GET git ref main -> merge commit sha');
    const home = await fetch(base + '/');
    const homeText = await home.text();
    check('web-home', home.status === 200 && homeText.includes('alice/hello'), 'web home lists alice/hello');
    const repoPage = await fetch(base + '/alice/hello');
    const repoText = await repoPage.text();
    check('web-repo', repoPage.status === 200 && repoText.includes('Hello world repo') && repoText.includes('git clone'), 'web repo page shows description + clone command');
    const issuesPage = await fetch(base + '/alice/hello/issues');
    const issuesText = await issuesPage.text();
    check('web-issues', issuesPage.status === 200 && issuesText.includes('Bug: hello crashes'), 'web issues page lists #1');
    const prPage = await fetch(base + '/alice/hello/pulls/1');
    const prText = await prPage.text();
    check('web-pr', prPage.status === 200 && prText.includes('Add feature') && prText.includes('src/feature.js'), 'web PR page shows title + changed file');
    r = await api('DELETE', '/api/repos/alice/hello/contents/src/main.js', aliceToken, { message: 'Remove main.js', sha: null, branch: 'main' });
    check('contents-delete', r.status === 200 && isSha(r.json.commit.sha), 'DELETE contents src/main.js -> 200, new commit');
    r = await api('GET', '/api/repos/alice/hello/contents/src/main.js?ref=main', null);
    check('contents-gone', r.status === 404, 'deleted file returns 404');
    r = await api('POST', '/api/users', null, { login: 'bob', name: 'Bob' });
    check('create-user-bob', r.status === 201 && r.json.login === 'bob', 'second user bob created');
    r = await api('GET', '/api/users/bob/repos', null);
    check('bob-repos-empty', r.status === 200 && Array.isArray(r.json) && r.json.length === 0, 'bob has no repos');
  } catch (e) {
    console.log('FAIL self-test-exception — ' + (e && e.stack ? e.stack.split('\n')[0] : e));
    results.push({ name: 'exception', ok: false });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
  }
  const passed = results.filter((x) => x.ok).length;
  console.log('SELF-TEST: ' + passed + '/' + results.length + ' passed');
  if (passed !== results.length) process.exit(1);
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
