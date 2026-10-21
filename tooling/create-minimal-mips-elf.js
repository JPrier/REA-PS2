#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';

// Synthetic parser/tool-invocation fixture only. It is not PS2SDK output and
// does not establish that a real PS2 program recompiles or executes correctly.
const out = process.argv[2];
if (!out) throw new Error('Usage: node tooling/create-minimal-mips-elf.js <output.elf>');
const b = Buffer.alloc(640);
b.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
b.writeUInt16LE(2, 16); b.writeUInt16LE(8, 18); b.writeUInt32LE(1, 20);
b.writeUInt32LE(0x1000, 24); b.writeUInt32LE(52, 28); b.writeUInt32LE(400, 32);
b.writeUInt32LE(0x20924001, 36); b.writeUInt16LE(52, 40); b.writeUInt16LE(32, 42); b.writeUInt16LE(1, 44);
b.writeUInt16LE(40, 46); b.writeUInt16LE(5, 48); b.writeUInt16LE(4, 50);
b.writeUInt32LE(1, 52); b.writeUInt32LE(256, 56); b.writeUInt32LE(0x1000, 60); b.writeUInt32LE(0x1000, 64);
b.writeUInt32LE(12, 68); b.writeUInt32LE(12, 72); b.writeUInt32LE(5, 76); b.writeUInt32LE(0x1000, 80);
// addiu v0, zero, 42; jr ra; nop
b.writeUInt32LE(0x2402002a, 256); b.writeUInt32LE(0x03e00008, 260); b.writeUInt32LE(0, 264);
b.writeUInt8(0, 268); b.write('main\0', 269, 'ascii');
b.writeUInt32LE(0, 280); // null symbol
b.writeUInt32LE(1, 296); b.writeUInt32LE(0x1000, 300); b.writeUInt32LE(12, 304); b.writeUInt8(0x12, 308); b.writeUInt16LE(1, 310);
const shstr = '\0.text\0.strtab\0.symtab\0.shstrtab\0'; b.write(shstr, 312, 'ascii');
function section(at, name, type, flags, addr, offset, size, link, info, align, entsize) {
  b.writeUInt32LE(name, at); b.writeUInt32LE(type, at + 4); b.writeUInt32LE(flags, at + 8); b.writeUInt32LE(addr, at + 12);
  b.writeUInt32LE(offset, at + 16); b.writeUInt32LE(size, at + 20); b.writeUInt32LE(link, at + 24); b.writeUInt32LE(info, at + 28);
  b.writeUInt32LE(align, at + 32); b.writeUInt32LE(entsize, at + 36);
}
section(440, 1, 1, 6, 0x1000, 256, 12, 0, 0, 4, 0);
section(480, 7, 3, 0, 0, 268, 5, 0, 0, 1, 0);
section(520, 15, 2, 0, 0, 280, 32, 2, 1, 4, 16);
section(560, 23, 3, 0, 0, 312, Buffer.byteLength(shstr), 0, 0, 1, 0);
await writeFile(out, b);
