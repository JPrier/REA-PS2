import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inspect, parseElf, parseIsoPrimaryVolume } from '../../apps/cli/src/main.js';

function elf32({ machine = 8, type = 2, phnum = 1 } = {}) {
  const b = Buffer.alloc(84); b.set([0x7f,69,76,70,1,1,1]); b.writeUInt16LE(type,16); b.writeUInt16LE(machine,18); b.writeUInt32LE(1,20); b.writeUInt32LE(0x1000,24); b.writeUInt32LE(52,28); b.writeUInt16LE(52,40); b.writeUInt16LE(32,42); b.writeUInt16LE(phnum,44);
  if (phnum) { b.writeUInt32LE(1,52); b.writeUInt32LE(84,56); b.writeUInt32LE(0x1000,60); b.writeUInt32LE(0,64); b.writeUInt32LE(0,68); b.writeUInt32LE(5,72); b.writeUInt32LE(4,76); }
  return b;
}
test('recognizes a bounded little-endian MIPS executable as a candidate only', () => {
  const r = parseElf(elf32()); assert.equal(r.target, 'PS2_EE_CANDIDATE'); assert.equal(r.entryPoint, 0x1000); assert.equal(r.loadSegments.length, 1);
  assert.match(r.limitations[0], /have not yet been validated/);
});
test('rejects an out-of-file load segment', () => { const b = elf32(); b.writeUInt32LE(0xfffffff0,56); assert.throws(() => parseElf(b), /out-of-bounds/); });
test('does not classify other machines as PS2', () => assert.equal(parseElf(elf32({ machine: 3 })).target, 'UNSUPPORTED'));
test('rejects truncated ELF headers', () => assert.throws(() => parseElf(Buffer.from([0x7f,69,76,70])), /complete ELF/));
test('rejects non-ISO input', () => assert.throws(() => parseIsoPrimaryVolume(Buffer.alloc(32768)), /descriptor/));
test('reads ISO9660 primary descriptor, SYSTEM.CNF, and root boot ELF', async () => {
  const b = Buffer.alloc(24 * 2048), p = 16 * 2048;
  b[p] = 1; b.write('CD001', p + 1, 'ascii'); b[p + 6] = 1; b.write('TEST_DISC', p + 40, 'ascii');
  const root = p + 156; b[root] = 34; b[root + 1] = 0; b.writeUInt32LE(20, root + 2); b.writeUInt32LE(2048, root + 10); b[root + 25] = 2; b[root + 32] = 1; b[root + 33] = 0;
  const d = 20 * 2048;
  const record = (o, sector, size, filename, flags = 0) => { const name = Buffer.from(filename, 'ascii'); const n = 33 + name.length + (name.length % 2 === 0 ? 1 : 0); b[o] = n; b[o + 1] = 0; b.writeUInt32LE(sector, o + 2); b.writeUInt32LE(size, o + 10); b[o + 25] = flags; b[o + 32] = name.length; name.copy(b, o + 33); return n; };
  const cnf = 'BOOT2 = cdrom0:\\SLUS_123.45;1\r\n';
  let at = d; at += record(at, 20, 2048, '\0', 2); at += record(at, 21, Buffer.byteLength(cnf), 'SYSTEM.CNF;1'); record(at, 22, 84, 'SLUS_123.45;1');
  b.write(cnf, 21 * 2048, 'ascii');
  const elf = b.subarray(22 * 2048, 22 * 2048 + 84); elf.set([0x7f,69,76,70,1,1,1]); elf.writeUInt16LE(2,16); elf.writeUInt16LE(8,18); elf.writeUInt32LE(1,20); elf.writeUInt16LE(52,40); elf.writeUInt16LE(32,42);
  const out = parseIsoPrimaryVolume(b); assert.equal(out.volumeId, 'TEST_DISC'); assert.equal(out.rootDirectory[0].name, 'SYSTEM.CNF');
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rea-ps2-iso-'));
  try { const file = path.join(dir, 'fixture.iso'); await writeFile(file, b); const result = await inspect(file); assert.equal(result.details.bootExecutable.name, 'SLUS_123.45'); assert.equal(result.details.bootExecutable.elf.target, 'PS2_EE_CANDIDATE'); }
  finally { await rm(dir, { recursive: true, force: true }); }
});
