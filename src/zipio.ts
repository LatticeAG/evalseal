/** Bounded STORE-only ZIP reader and writer for attestation packs (spec §9.2). */

export const PUBLIC_ENTRIES = [
  "audit.jsonl", "cases.json", "certificate.json", "checkpoint.json",
  "keyring.json", "manifest.json", "release.json", "report.pdf",
  "result.json", "scope.txt", "target.json",
];
export const PRIVATE_EXTRA = ["evidence.json", "transcript.bin"];

export const MAX_ENTRY_DEFAULT = 32 * 1024 * 1024;
export const MAX_ENTRY_EVIDENCE = 336 * 1024 * 1024;
export const MAX_ENTRY_TRANSCRIPT = 448 * 1024 * 1024;
export const MAX_PUBLIC_PACK = 32 * 1024 * 1024;
export const MAX_PRIVATE_PACK = 832 * 1024 * 1024;
export const MAX_ENTRIES = 16;

const EOCD_SIG = 0x06054b50;
const CDIR_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

export class ZipError extends Error {
  code: string;
  constructor(code: string, message = "") { super(message || code); this.code = code; }
}

// CRC-32 (IEEE) ------------------------------------------------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(data: Buffer | Uint8Array): number {
  let crc = 0xffffffff;
  for (const b of data) crc = CRC_TABLE[(crc ^ b) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function entryBound(name: string): number {
  if (name === "evidence.json") return MAX_ENTRY_EVIDENCE;
  if (name === "transcript.bin") return MAX_ENTRY_TRANSCRIPT;
  return MAX_ENTRY_DEFAULT;
}

const validName = (name: string) => PUBLIC_ENTRIES.includes(name) || PRIVATE_EXTRA.includes(name);

export interface DirEntry { name: string; size: number; crc: number; offset: number; }

export function readDirectory(data: Buffer): DirEntry[] {
  if (data.length < 22) throw new ZipError("PACK_ENTRY_INVALID", "too small for ZIP");
  const tail = data.subarray(Math.max(0, data.length - (22 + 65536)));
  const sig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const idx = tail.lastIndexOf(sig);
  if (idx < 0) throw new ZipError("PACK_ENTRY_INVALID", "no end of central directory");
  const eocd = tail.subarray(idx, idx + 22);
  if (eocd.length < 22) throw new ZipError("PACK_ENTRY_INVALID", "truncated EOCD");
  const disk = eocd.readUInt16LE(4), cdDisk = eocd.readUInt16LE(6);
  const nDisk = eocd.readUInt16LE(8), nTotal = eocd.readUInt16LE(10);
  const cdSize = eocd.readUInt32LE(12), cdOff = eocd.readUInt32LE(16), comLen = eocd.readUInt16LE(20);
  if (comLen !== 0 || disk !== 0 || cdDisk !== 0 || nDisk !== nTotal) {
    throw new ZipError("PACK_ENTRY_INVALID", "multi-disk/comment archives unsupported");
  }
  if (nTotal > MAX_ENTRIES) throw new ZipError("PACK_SIZE_LIMIT", "entry count exceeds bound");
  if (cdOff + cdSize > data.length) throw new ZipError("PACK_ENTRY_INVALID", "central directory out of range");
  const entries: DirEntry[] = [];
  const seen = new Set<string>();
  let pos = cdOff;
  for (let i = 0; i < nTotal; i++) {
    if (pos + 46 > data.length || data.readUInt32LE(pos) !== CDIR_SIG) {
      throw new ZipError("PACK_ENTRY_INVALID", "bad central directory entry");
    }
    const flags = data.readUInt16LE(pos + 8), method = data.readUInt16LE(pos + 10);
    const crc = data.readUInt32LE(pos + 16), csize = data.readUInt32LE(pos + 20), usize = data.readUInt32LE(pos + 24);
    const nlen = data.readUInt16LE(pos + 28), elen = data.readUInt16LE(pos + 30), clen = data.readUInt16LE(pos + 32);
    const lhoff = data.readUInt32LE(pos + 42);
    const nameB = data.subarray(pos + 46, pos + 46 + nlen);
    if ([...nameB].some(b => b > 0x7f)) throw new ZipError("PACK_PATH_INVALID", "non-ASCII entry name");
    const name = nameB.toString("ascii");
    if (!validName(name) || seen.has(name)) throw new ZipError("PACK_PATH_INVALID", "entry outside allowlist");
    seen.add(name);
    if (flags !== 0 || method !== 0 || clen !== 0 || elen !== 0) {
      throw new ZipError("PACK_ENTRY_INVALID", "only plain STORE entries are supported");
    }
    if (csize !== usize) throw new ZipError("PACK_ENTRY_INVALID", "STORE entry with mismatched sizes");
    if (usize > entryBound(name)) throw new ZipError("PACK_SIZE_LIMIT", "declared size exceeds entry bound");
    entries.push({ name, size: usize, crc, offset: lhoff });
    pos += 46 + nlen + elen + clen;
  }
  const total = entries.reduce((n, e) => n + e.size, 0);
  if (total > MAX_PRIVATE_PACK) throw new ZipError("PACK_SIZE_LIMIT", "declared total exceeds pack bound");
  if (!entries.some(e => PRIVATE_EXTRA.includes(e.name)) && total > MAX_PUBLIC_PACK) {
    throw new ZipError("PACK_SIZE_LIMIT", "declared total exceeds public pack bound");
  }
  return entries;
}

export function extract(data: Buffer, entries: DirEntry[]): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const e of entries) {
    const off = e.offset;
    if (off + 30 > data.length || data.readUInt32LE(off) !== LOCAL_SIG) {
      throw new ZipError("PACK_ENTRY_INVALID", "bad local header");
    }
    const flags = data.readUInt16LE(off + 6), method = data.readUInt16LE(off + 8);
    const crc = data.readUInt32LE(off + 14), csize = data.readUInt32LE(off + 18), usize = data.readUInt32LE(off + 22);
    const nlen = data.readUInt16LE(off + 26), elen = data.readUInt16LE(off + 28);
    const nameB = data.subarray(off + 30, off + 30 + nlen);
    if (flags !== 0 || method !== 0) throw new ZipError("PACK_ENTRY_INVALID", "unsupported local entry");
    if ([...nameB].some(b => b > 0x7f)) throw new ZipError("PACK_PATH_INVALID", "non-ASCII local name");
    if (nameB.toString("ascii") !== e.name) throw new ZipError("PACK_PATH_INVALID", "local/central name mismatch");
    if (csize !== e.size || usize !== e.size) throw new ZipError("PACK_ENTRY_INVALID", "local size mismatch");
    const start = off + 30 + nlen + elen;
    const end = start + usize;
    if (end > data.length) throw new ZipError("PACK_ENTRY_INVALID", "entry data out of range");
    const blob = data.subarray(start, end);
    if (crc32(blob) !== crc) throw new ZipError("PACK_ENTRY_INVALID", "CRC mismatch");
    out.set(e.name, blob);
  }
  return out;
}

export function readPack(data: Buffer): Map<string, Buffer> {
  const entries = readDirectory(data);
  return extract(data, entries);
}

/** Byte-identical STORE archive: sorted ASCII paths, DOS epoch, unix 0644. */
export function writePack(files: Map<string, Buffer>): Buffer {
  const names = [...files.keys()].sort();
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const name of names) {
    const data = files.get(name)!;
    const nameB = Buffer.from(name, "ascii");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(LOCAL_SIG, 0);
    local.writeUInt16LE(20, 4);        // version needed
    local.writeUInt16LE(0, 6);         // flags
    local.writeUInt16LE(0, 8);         // method: STORE
    local.writeUInt16LE(0, 10);        // mod time (DOS epoch)
    local.writeUInt16LE(33, 12);       // mod date 1980-01-01
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameB.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, nameB, data);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(CDIR_SIG, 0);
    cd.writeUInt16LE(20 | (3 << 8), 4); // version made by: unix
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(33, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameB.length, 28);
    // extra/comment/disk/iattr all zero
    cd.writeUInt32LE(0o100644 << 16 >>> 0, 38); // external attr
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, nameB]));
    offset += 30 + nameB.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(names.length, 8);
  eocd.writeUInt16LE(names.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, cdBuf, eocd]);
}
