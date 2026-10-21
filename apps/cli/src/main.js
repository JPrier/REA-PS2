#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { createReadStream, existsSync } from 'node:fs';
import { mkdir, open, readFile, realpath, rename, stat, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const EXIT = { success: 0, invalidInput: 2, prerequisite: 3, unsupported: 4, analysis: 5, compile: 6, runtime: 7, verify: 8, cancelled: 9, internal: 10, timeout: 11 };
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
class ReaError extends Error { constructor(code, message, details = {}) { super(message); this.code = code; this.details = details; } }

function need(ok, message, details) { if (!ok) throw new ReaError('INVALID_INPUT', message, details); }
function u16(b, o, le) { need(o >= 0 && o + 2 <= b.length, 'Truncated ELF field', { offset: o }); return le ? b.readUInt16LE(o) : b.readUInt16BE(o); }
function u32(b, o, le) { need(o >= 0 && o + 4 <= b.length, 'Truncated ELF field', { offset: o }); return le ? b.readUInt32LE(o) : b.readUInt32BE(o); }

export function parseElf(b) {
  need(b.length >= 52 && b.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])), 'Input is not a complete ELF file');
  const cls = b[4], data = b[5]; need((cls === 1 || cls === 2) && (data === 1 || data === 2), 'Unsupported ELF class or byte order', { elfClass: cls, dataEncoding: data });
  const le = data === 1, hsize = cls === 1 ? 52 : 64; need(b.length >= hsize, 'Truncated ELF header');
  const type = u16(b, 16, le), machine = u16(b, 18, le), entry = cls === 1 ? u32(b, 24, le) : Number(b.readBigUInt64LE(24));
  const phoff = cls === 1 ? u32(b, 28, le) : Number(le ? b.readBigUInt64LE(32) : b.readBigUInt64BE(32));
  const ehsize = u16(b, cls === 1 ? 40 : 52, le), phentsize = u16(b, cls === 1 ? 42 : 54, le), phnum = u16(b, cls === 1 ? 44 : 56, le);
  need(ehsize >= hsize && phnum <= 4096, 'Invalid ELF header size or program-header count', { ehsize, phnum });
  const minPh = cls === 1 ? 32 : 56; need(phentsize >= minPh || phnum === 0, 'Invalid program-header entry size', { phentsize });
  need(phoff + phentsize * phnum <= b.length || phnum === 0, 'Program-header table exceeds file bounds');
  const segments = [];
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize, kind = u32(b, o, le);
    if (kind !== 1) continue;
    const fileOffset = cls === 1 ? u32(b, o + 4, le) : Number(le ? b.readBigUInt64LE(o + 8) : b.readBigUInt64BE(o + 8));
    const vaddr = cls === 1 ? u32(b, o + 8, le) : Number(le ? b.readBigUInt64LE(o + 16) : b.readBigUInt64BE(o + 16));
    const fileSize = cls === 1 ? u32(b, o + 16, le) : Number(le ? b.readBigUInt64LE(o + 32) : b.readBigUInt64BE(o + 32));
    const memSize = cls === 1 ? u32(b, o + 20, le) : Number(le ? b.readBigUInt64LE(o + 40) : b.readBigUInt64BE(o + 40));
    const flags = cls === 1 ? u32(b, o + 24, le) : u32(b, o + 4, le);
    need(fileOffset + fileSize <= b.length && memSize >= fileSize, 'Invalid or out-of-bounds load segment', { index: i, fileOffset, fileSize, memSize });
    segments.push({ fileOffset, virtualAddress: vaddr, fileSize, memorySize: memSize, executable: Boolean(flags & 1) });
  }
  const ps2Candidate = machine === 8 && cls === 1 && le && type === 2;
  return { format: 'ELF', elfClass: cls === 1 ? 32 : 64, endianness: le ? 'little' : 'big', type, machine, entryPoint: entry, programHeaders: phnum, loadSegments: segments, target: ps2Candidate ? 'PS2_EE_CANDIDATE' : 'UNSUPPORTED', limitations: ps2Candidate ? ['ELF metadata indicates little-endian MIPS32 executable; EE processor flags and instruction profile have not yet been validated.'] : ['ELF does not match the currently recognized PS2 EE executable profile.'] };
}

export function parseIsoPrimaryVolume(b) {
  const sector = 2048; let pvd;
  for (let i = 16; i < Math.min(16 + 256, Math.floor(b.length / sector)); i++) {
    const o = i * sector; if (b.toString('ascii', o + 1, o + 6) === 'CD001' && b[o + 6] === 1 && b[o] === 1) { pvd = o; break; }
  }
  need(pvd !== undefined, 'No ISO9660 primary volume descriptor found');
  const root = pvd + 156, len = b[root]; need(len >= 34 && root + len <= b.length, 'Invalid ISO9660 root directory record');
  const extent = u32(b, root + 2, true), size = u32(b, root + 10, true);
  need((extent + Math.ceil(size / sector)) * sector <= b.length, 'ISO9660 root directory exceeds image bounds');
  const rootData = b.subarray(extent * sector, extent * sector + size);
  return parseIsoRootDirectory(rootData, b.toString('ascii', pvd + 40, pvd + 72).replace(/\0+$/, '').trim());
}

function parseIsoRootDirectory(data, volumeId) {
  const sector = 2048, files = [];
  for (let o = 0; o < data.length;) {
    const n = data[o]; if (n === 0) { o = (Math.floor(o / sector) + 1) * sector; continue; }
    need(n >= 34 && o + n <= data.length, 'Malformed ISO9660 directory record', { offset: o });
    const nameLen = data[o + 32]; need(33 + nameLen <= n, 'Malformed ISO9660 filename record', { offset: o });
    const name = data.toString('ascii', o + 33, o + 33 + nameLen).replace(/;\d+$/, '').replace(/\.$/, '');
    if (name !== '\0' && name !== '\x01') files.push({ name, directory: Boolean(data[o + 25] & 2), extent: u32(data, o + 2, true), size: u32(data, o + 10, true) });
    o += n;
  }
  return { volumeId, rootDirectory: files, limitations: ['ISO9660 root directory only; nested filesystem traversal and Joliet/Rock Ridge are not implemented.'] };
}

async function readAt(handle, size, position) {
  const buffer = Buffer.alloc(size); let offset = 0;
  while (offset < size) {
    const { bytesRead } = await handle.read(buffer, offset, size - offset, position + offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return buffer.subarray(0, offset);
}

export async function inspect(input) {
  const p = await realpath(input); const s = await stat(p); need(s.isFile(), 'Input must be a regular file', { path: p });
  need(s.size > 0 && s.size <= 8 * 1024 ** 3, 'Input size is empty or exceeds the 8 GiB safety limit', { size: s.size });
  const handle = await open(p, 'r');
  try {
  const magic = await readAt(handle, 4, 0);
  let format, details;
  if (magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    need(s.size <= 512 * 1024 * 1024, 'ELF exceeds the 512 MiB in-memory parser limit', { size: s.size });
    const data = await readAt(handle, s.size, 0); format = 'ELF'; details = parseElf(data);
  } else if (s.size >= 17 * 2048) {
    const sector = 2048; let pvd;
    for (let i = 16; i < Math.min(16 + 256, Math.floor(s.size / sector)); i++) {
      const desc = await readAt(handle, 7, i * sector);
      if (desc[0] === 1 && desc.toString('ascii', 1, 6) === 'CD001' && desc[6] === 1) { pvd = i * sector; break; }
    }
    if (pvd === undefined) throw new ReaError('INVALID_INPUT', 'No ISO9660 primary volume descriptor found');
    const volumeHeader = await readAt(handle, 2048, pvd), rootRecord = volumeHeader.subarray(156, 190);
    need(rootRecord.length === 34 && rootRecord[0] >= 34, 'Invalid ISO9660 root directory record');
    const rootExtent = u32(rootRecord, 2, true), rootSize = u32(rootRecord, 10, true), rootOffset = rootExtent * sector;
    need(rootSize <= 64 * 1024 * 1024 && rootOffset + rootSize <= s.size, 'ISO9660 root directory exceeds bounded size or image bounds', { rootSize, rootOffset });
    const rootData = await readAt(handle, rootSize, rootOffset);
    need(rootData.length === rootSize, 'Truncated ISO9660 root directory');
    format = 'ISO'; details = parseIsoRootDirectory(rootData, volumeHeader.toString('ascii', 40, 72).replace(/\0+$/, '').trim());
    const system = details.rootDirectory.find(f => !f.directory && f.name.toUpperCase() === 'SYSTEM.CNF');
    if (system) {
      const systemOffset = system.extent * sector;
      need(system.size <= 1024 * 1024 && systemOffset + system.size <= s.size, 'SYSTEM.CNF exceeds bounded ISO file limits');
      const cnf = (await readAt(handle, system.size, systemOffset)).toString('ascii');
      const boot = cnf.match(/^\s*BOOT2\s*=\s*cdrom0:\\([^;\r\n]+)(?:;\d+)?/im);
    if (boot) {
        const bootName = boot[1].replaceAll('/', '\\').split('\\').filter(Boolean).at(-1).toUpperCase();
        const executable = details.rootDirectory.find(f => !f.directory && f.name.toUpperCase() === bootName);
        if (executable) {
          const fileOffset = executable.extent * sector;
          need(executable.size <= 512 * 1024 * 1024 && fileOffset + executable.size <= s.size, 'Boot executable exceeds bounded ISO file limits', { size: executable.size });
          const elf = await readAt(handle, executable.size, fileOffset);
          need(elf.length === executable.size, 'Truncated ISO boot executable');
          details.bootExecutable = { name: executable.name, size: executable.size, fileOffset, sha256: createHash('sha256').update(elf).digest('hex') };
          if (elf.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) details.bootExecutable.elf = parseElf(elf);
          else details.bootExecutable.diagnostic = 'SYSTEM.CNF boot path was found, but the root-level target is not an ELF file.';
        } else details.bootExecutable = { path: boot[1], status: 'not_in_root_directory', diagnostic: 'The SYSTEM.CNF target is not in the ISO root; nested directory lookup is not implemented.' };
      } else details.bootExecutable = { status: 'unrecognized_system_cnf', diagnostic: 'No supported BOOT2=cdrom0 path was found.' };
    } else details.bootExecutable = { status: 'system_cnf_missing', diagnostic: 'SYSTEM.CNF was not found in the ISO root directory.' };
  } else throw new ReaError('INVALID_INPUT', 'Input is neither a recognized ELF nor an ISO9660 image', { size: s.size });
  const sha256 = await hashFile(p);
  return { schemaVersion: 1, path: p, size: s.size, sha256, format, details };
  } finally { await handle.close(); }
}

async function doctor() {
  const commands = ['ghidraRun', 'analyzeHeadless', 'pcsx2', 'ps2_analyzer', 'ps2_recomp', 'ps2_runtime', 'cmake', 'g++']; const found = {};
  for (const cmd of commands) {
    try { const { execFile } = await import('node:child_process'); const { promisify } = await import('node:util'); const run = promisify(execFile); const r = await run(os.platform() === 'win32' ? 'where.exe' : 'which', [cmd]); found[cmd] = { available: true, path: r.stdout.trim().split(/\r?\n/)[0] }; }
    catch { found[cmd] = { available: false }; }
  }
  const configuredAnalyzer = process.env.REA_PS2_ANALYZER;
  if (configuredAnalyzer) found.ps2_analyzer = { available: await exists(configuredAnalyzer), path: configuredAnalyzer, source: 'REA_PS2_ANALYZER' };
  const configuredRecompiler = process.env.REA_PS2_RECOMP;
  if (configuredRecompiler) found.ps2_recomp = { available: await exists(configuredRecompiler), path: configuredRecompiler, source: 'REA_PS2_RECOMP' };
  for (const [name, relative] of Object.entries({
    ps2_analyzer: process.platform === 'win32' ? '.upstream/ps2recomp/build/ps2xAnalyzer/Release/ps2_analyzer.exe' : '.upstream/ps2recomp/build/ps2xAnalyzer/ps2_analyzer',
    ps2_recomp: process.platform === 'win32' ? '.upstream/ps2recomp/build/ps2xRecomp/Release/ps2_recomp.exe' : '.upstream/ps2recomp/build/ps2xRecomp/ps2_recomp',
    ps2_runtime: process.platform === 'win32' ? '.upstream/ps2recomp/build/ps2xRuntime/Release/ps2_runtime.lib' : '.upstream/ps2recomp/build/ps2xRuntime/libps2_runtime.a'
  })) {
    if (!found[name].available) { const local = path.join(REPO_ROOT, relative); if (await exists(local)) found[name] = { available: true, path: local, source: 'pinned local checkout/build' }; }
  }
  for (const [name, relative] of Object.entries({
    ghidraRun: '.upstream/tools/ghidra/ghidra_12.1.4_PUBLIC/ghidraRun.bat',
    analyzeHeadless: '.upstream/tools/ghidra/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat',
    pcsx2: '.upstream/tools/PCSX2/pcsx2-qt.exe'
  })) {
    if (!found[name].available) { const local = path.join(REPO_ROOT, relative); if (await exists(local)) found[name] = { available: true, path: local, source: 'pinned local tool install' }; }
  }
  const ghidraReady = found.analyzeHeadless.available;
  const recompReady = found.ps2_recomp.available;
  return { schemaVersion: 1, host: { platform: process.platform, architecture: process.arch, node: process.version }, tools: found, lanes: { inputInspection: 'available', ps2ElfHeuristicAnalysis: found.ps2_analyzer.available ? 'available_unverified' : 'unavailable', staticAnalysis: ghidraReady ? 'unverified' : 'unavailable', nativeRecompilation: recompReady ? 'unverified' : 'unavailable', pcsx2Reference: found.pcsx2.available ? 'unverified' : 'unavailable' }, status: 'foundation_only', blockers: ['REA/Ghidra analysis is not yet connected to the pipeline.', 'Native smoke code dispatches, but guest register and memory results are not independently verified.', 'PCSX2 differential tests and interactive gameplay verification have not passed; the BIOS prerequisite is currently absent.'] };
}

async function exists(file) { try { await access(file); return true; } catch { return false; } }

async function runAnalyzer(input, args) {
  const workspaceFlag = args.indexOf('--workspace');
  const workspaceArg = workspaceFlag >= 0 ? args[workspaceFlag + 1] : undefined;
  if (workspaceFlag >= 0) need(Boolean(workspaceArg), '--workspace requires a directory path');
  const explicit = args.findIndex(a => a === '--ps2-analyzer');
  const tool = explicit >= 0 ? args[explicit + 1] : process.env.REA_PS2_ANALYZER;
  if (explicit >= 0) need(Boolean(tool), '--ps2-analyzer requires a path');
  need(input.format === 'ELF' || input.details.bootExecutable?.fileOffset !== undefined,
    'No supported root-level boot ELF is available for analysis', { code: 'BOOT_ELF_UNAVAILABLE', bootExecutable: input.details.bootExecutable });
  const elfProfile = input.format === 'ELF' ? input.details : input.details.bootExecutable.elf;
  if (!elfProfile || elfProfile.target !== 'PS2_EE_CANDIDATE')
    throw new ReaError('UNSUPPORTED_TARGET', 'Input does not contain an ELF that matches the currently recognized PS2 EE candidate profile', { format: input.format, target: elfProfile?.target ?? 'NOT_ELF' });
  const selected = tool || path.join(REPO_ROOT, process.platform === 'win32'
    ? '.upstream/ps2recomp/build/ps2xAnalyzer/Release/ps2_analyzer.exe'
    : '.upstream/ps2recomp/build/ps2xAnalyzer/ps2_analyzer');
  if (!(await exists(selected))) throw new ReaError('PREREQUISITE_MISSING', 'PS2Recomp ps2_analyzer was not found. Build the pinned dependency or set REA_PS2_ANALYZER.', { expectedPath: selected, environmentVariable: 'REA_PS2_ANALYZER' });
  const root = path.resolve(workspaceArg || path.join('.rea-ps2', 'workspaces', input.sha256));
  const inputPath = path.join(root, 'input', 'boot.elf'); const outDir = path.join(root, 'analysis');
  await mkdir(path.dirname(inputPath), { recursive: true }); await mkdir(outDir, { recursive: true });
  let bytes;
  if (input.format === 'ELF') bytes = await readFile(input.path);
  else {
    const handle = await open(input.path, 'r');
    try { bytes = await readAt(handle, input.details.bootExecutable.size, input.details.bootExecutable.fileOffset); }
    finally { await handle.close(); }
  }
  if (!(await exists(inputPath))) await writeFile(inputPath, bytes, { flag: 'wx' });
  const elfHash = createHash('sha256').update(bytes).digest('hex');
  need(elfHash === (input.format === 'ELF' ? input.sha256 : input.details.bootExecutable.sha256), 'Boot ELF identity changed during ingestion');
  const configPath = path.join(outDir, 'ps2recomp.toml'), stagePath = path.join(outDir, 'stage.json');
  const toolSha256 = await hashFile(selected);
  if (await exists(configPath) && await exists(stagePath)) {
    try {
      const previous = JSON.parse(await readFile(stagePath, 'utf8'));
      const existing = await readFile(configPath);
      if (previous.inputSha256 === elfHash && previous.tool === selected && previous.toolSha256 === toolSha256 && previous.outputSha256 === createHash('sha256').update(existing).digest('hex'))
        return { schemaVersion: 1, status: 'heuristic_analysis_complete', analysisMethod: 'PS2Recomp native analyzer', confidence: 'heuristic; not Ghidra-reviewed', inputSha256: input.sha256, bootElfSha256: elfHash, workspace: root, config: configPath, cache: 'hit', limitations: ['The PS2Recomp analyzer uses ELF symbols/JAL heuristics when Ghidra output is absent. This is not an exhaustive function map.', 'This analysis artifact itself does not establish translation, runtime linking, or execution.'] };
    } catch { /* invalid or partial stage marker is rebuilt below */ }
  }
  const tmpConfig = `${configPath}.${process.pid}.tmp`, { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  try {
    await promisify(execFile)(selected, [inputPath, tmpConfig], { timeout: 15 * 60 * 1000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
    const generated = await readFile(tmpConfig);
    need(generated.length > 0 && generated.toString('utf8').includes('[general]'), 'PS2Recomp analyzer output failed schema sanity checks', { outputBytes: generated.length });
    const outputSha256 = createHash('sha256').update(generated).digest('hex');
    await rename(tmpConfig, configPath);
    const marker = { schemaVersion: 1, inputSha256: elfHash, tool: selected, toolSha256, toolchainRevision: 'eb8688b2fd191129f103a39543002c005b33409c', outputSha256, completedAt: new Date().toISOString(), method: 'PS2Recomp heuristic analyzer; no Ghidra export supplied' };
    await writeJsonAtomic(stagePath, marker);
    await writeJsonAtomic(path.join(root, 'input-manifest.json'), { schemaVersion: 1, inputSha256: input.sha256, bootElfSha256: elfHash, sourceFormat: input.format, sourcePath: input.path, bootExecutable: input.details.bootExecutable ?? null });
    await writeJsonAtomic(path.join(root, 'environment-manifest.json'), { schemaVersion: 1, host: { platform: process.platform, architecture: process.arch, node: process.version }, ps2RecompRevision: marker.toolchainRevision, analyzerSha256: toolSha256 });
    return { schemaVersion: 1, status: 'heuristic_analysis_complete', analysisMethod: 'PS2Recomp native analyzer', confidence: 'heuristic; not Ghidra-reviewed', inputSha256: input.sha256, bootElfSha256: elfHash, workspace: root, config: configPath, cache: 'miss', limitations: ['The PS2Recomp analyzer uses ELF symbols/JAL heuristics when Ghidra output is absent. This is not an exhaustive function map.', 'This analysis artifact itself does not establish translation, runtime linking, or execution.'] };
  } catch (error) {
    await import('node:fs/promises').then(fs => fs.rm(tmpConfig, { force: true }));
    throw new ReaError('ANALYSIS_FAILURE', 'PS2Recomp analyzer failed or produced invalid output', { exitCode: error.code, stderr: String(error.stderr || '').slice(-4096), stdout: String(error.stdout || '').slice(-4096), message: error.message });
  }
}

async function runRecompiler(input, args) {
  const analysis = await runAnalyzer(input, args);
  const overrideAt = args.indexOf('--ps2-recomp');
  const override = overrideAt >= 0 ? args[overrideAt + 1] : process.env.REA_PS2_RECOMP;
  if (overrideAt >= 0) need(Boolean(override), '--ps2-recomp requires a path');
  const tool = override || path.join(REPO_ROOT, process.platform === 'win32'
    ? '.upstream/ps2recomp/build/ps2xRecomp/Release/ps2_recomp.exe'
    : '.upstream/ps2recomp/build/ps2xRecomp/ps2_recomp');
  if (!(await exists(tool))) throw new ReaError('PREREQUISITE_MISSING', 'PS2Recomp recompiler was not found. Build the pinned dependency or set REA_PS2_RECOMP.', { expectedPath: tool, environmentVariable: 'REA_PS2_RECOMP' });
  const work = path.join(analysis.workspace, 'recomp'); await mkdir(work, { recursive: true });
  const configSource = await readFile(analysis.config, 'utf8');
  const config = configSource.replace(/(^\[general\][\s\S]*?^output\s*=\s*)"[^"]*"/m, '$1"./generated/"');
  need(config !== configSource, 'PS2Recomp TOML output path could not be isolated to this build workspace');
  const configPath = path.join(work, 'config.toml');
  await writeFile(configPath, config);
  const outputDir = path.join(work, 'generated'); const markerPath = path.join(work, 'stage.json');
  const configSha256 = createHash('sha256').update(config).digest('hex'), toolSha256 = await hashFile(tool);
  if (await exists(markerPath) && await exists(path.join(outputDir, 'register_functions.cpp'))) {
    try {
      const marker = JSON.parse(await readFile(markerPath, 'utf8'));
      const files = await import('node:fs/promises').then(fs => fs.readdir(outputDir));
      const currentHash = await hashFiles(outputDir, files);
      if (marker.configSha256 === configSha256 && marker.tool === tool && marker.toolSha256 === toolSha256 && marker.outputSha256 === currentHash)
        return await runNativeBuild({ ...analysis, translationCache: 'hit', translatedFunctions: marker.translatedFunctions, translatedSource: outputDir, outputSha256: marker.outputSha256, unhandledInstructions: marker.unhandledInstructions }, args);
    } catch { /* incomplete cache is retranslated */ }
  }
  const { execFile } = await import('node:child_process'); const { promisify } = await import('node:util');
  try {
    const { stdout, stderr } = await promisify(execFile)(tool, [configPath], { cwd: work, timeout: 15 * 60 * 1000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
    const report = `${stdout}\n${stderr}`;
    const compiledMatch = report.match(/Functions processed:\s*\d+,\s*recompiled:\s*(\d+)/i);
    const unhandledMatch = report.match(/Unhandled instructions:\s*(\d+)/i);
    const errorsMatch = report.match(/Warnings:\s*\d+,\s*errors:\s*(\d+)/i);
    need(compiledMatch && unhandledMatch && errorsMatch, 'PS2Recomp did not emit its expected machine-readable summary fields', { tail: report.slice(-4000) });
    const unhandledInstructions = Number(unhandledMatch[1]), errors = Number(errorsMatch[1]);
    need(errors === 0, 'PS2Recomp reported translation errors', { errors, report: report.slice(-4000) });
    const { readdir } = await import('node:fs/promises'); const generatedFiles = await readdir(outputDir);
    need(generatedFiles.includes('register_functions.cpp') && generatedFiles.some(f => f.endsWith('.cpp')), 'Generated code or function registration is missing', { generatedFiles });
    const outputSha256 = await hashFiles(outputDir, generatedFiles);
    const marker = { schemaVersion: 1, configSha256, tool, toolSha256, toolchainRevision: 'eb8688b2fd191129f103a39543002c005b33409c', outputSha256, translatedFunctions: Number(compiledMatch[1]), unhandledInstructions, completedAt: new Date().toISOString() };
    await writeJsonAtomic(markerPath, marker);
    return await runNativeBuild({ ...analysis, translationCache: 'miss', translatedFunctions: marker.translatedFunctions, unhandledInstructions, translatedSource: outputDir, outputSha256, translationWarnings: unhandledInstructions ? [`PS2Recomp reported ${unhandledInstructions} unhandled instructions.`] : [] }, args);
  } catch (error) {
    if (error instanceof ReaError) throw error;
    throw new ReaError('ANALYSIS_FAILURE', 'PS2Recomp translation failed or its generated artifacts did not validate', { exitCode: error.code, stderr: String(error.stderr || '').slice(-4096), stdout: String(error.stdout || '').slice(-4096), message: error.message });
  }
}

async function launchNative(input, args) {
  const build = await runRecompiler(input, args);
  const timeoutIndex = args.indexOf('--timeout-ms');
  const timeoutMs = timeoutIndex < 0 ? 0 : Number(args[timeoutIndex + 1]);
  if (timeoutIndex >= 0) need(Number.isSafeInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 86_400_000, '--timeout-ms must be an integer from 100 through 86400000');
  const elf = path.join(build.workspace, 'input', 'boot.elf');
  const { spawn } = await import('node:child_process');
  const executionDir = path.join(build.workspace, 'execution'); await mkdir(executionDir, { recursive: true });
  const startedAt = new Date().toISOString(), start = Date.now();
  const child = spawn(build.executable, [elf], { stdio: 'inherit', windowsHide: false, cwd: build.workspace });
  let cancelled = false, timedOut = false;
  const onInterrupt = () => { cancelled = true; child.kill(); };
  const timeout = timeoutMs ? setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs) : null;
  process.once('SIGINT', onInterrupt);
  try {
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (exitCode, signal) => resolve({ exitCode, signal }));
    });
    if (cancelled || timedOut) {
      const status = cancelled ? 'cancelled' : 'timed_out';
      const blockers = [cancelled ? 'Execution ended by cancellation; guest behavior and playability remain unverified.' : 'Execution exceeded its configured timeout; guest behavior and playability remain unverified.'];
      const report = { schemaVersion: 1, status, inputSha256: input.sha256, executableSha256: build.executableSha256, startedAt, elapsedMs: Date.now() - start, exitCode: code.exitCode, signal: code.signal, timeoutMs: timeoutMs || undefined, capability: 'native process launched and stopped before behavioral verification', blockers };
      await writeJsonAtomic(path.join(executionDir, 'run.json'), report);
      if (timedOut) throw new ReaError('TIMEOUT', 'Native runner exceeded its configured timeout', { timeoutMs });
      throw new ReaError('CANCELLED', 'Native runner was cancelled by the user', { signal: code.signal });
    }
    if (code.exitCode !== 0) {
      const report = { schemaVersion: 1, status: 'runtime_failed', inputSha256: input.sha256, executableSha256: build.executableSha256, startedAt, elapsedMs: Date.now() - start, ...code, capability: 'native process launched and exited with failure', blockers: ['Runtime exit status does not identify the underlying guest behavior without further diagnosis.'] };
      await writeJsonAtomic(path.join(executionDir, 'run.json'), report);
      throw new ReaError('RUNTIME_FAILURE', 'Native runner exited with a failure status', { ...code, executable: build.executable });
    }
    const report = { schemaVersion: 1, status: 'native_process_exited_unverified', inputSha256: input.sha256, executableSha256: build.executableSha256, startedAt, elapsedMs: Date.now() - start, exitCode: code.exitCode, capability: 'native process launched and exited', blockers: ['Process exit does not prove correct game behavior, compatibility, or playability.', 'No reference comparison or automated behavioral assertions ran.'] };
    await writeJsonAtomic(path.join(executionDir, 'run.json'), report);
    return { ...build, ...report };
  } catch (error) {
    if (error instanceof ReaError) throw error;
    throw new ReaError('RUNTIME_FAILURE', 'Native runner could not be launched', { message: error.message, executable: build.executable });
  } finally { if (timeout) clearTimeout(timeout); process.removeListener('SIGINT', onInterrupt); }
}

async function runNativeBuild(result, args) {
  const source = path.resolve(process.env.REA_PS2RECOMP_SOURCE || path.join(REPO_ROOT, '.upstream/ps2recomp'));
  need(await exists(path.join(source, 'CMakeLists.txt')), 'PS2Recomp CMake source is unavailable', { source, environmentVariable: 'REA_PS2RECOMP_SOURCE' });
  const lock = JSON.parse(await readFile(path.join(REPO_ROOT, 'DEPENDENCY_LOCK.json'), 'utf8'));
  const expectedSourceRevision = lock.upstreams.ps2recomp.revision;
  const run = async (exe, argv, options = {}) => {
    const { execFile } = await import('node:child_process'); const { promisify } = await import('node:util');
    return promisify(execFile)(exe, argv, { timeout: 30 * 60 * 1000, maxBuffer: 32 * 1024 * 1024, windowsHide: true, ...options });
  };
  let sourceRevision;
  try { sourceRevision = (await run('git', ['-C', source, 'rev-parse', 'HEAD'])).stdout.trim(); }
  catch (error) { throw new ReaError('PREREQUISITE_MISSING', 'Git could not identify the PS2Recomp source revision', { source, message: error.message }); }
  need(sourceRevision === expectedSourceRevision, 'PS2Recomp source revision does not match the lock manifest', { expected: expectedSourceRevision, actual: sourceRevision });
  const depDirs = {};
  const depLockKeys = { ELFIO: 'elfio', TOML11: 'toml11', FMT: 'fmt', LIBDWARF: 'libdwarf', RABBITIZER: 'rabbitizer', NLOHMANN_JSON: 'nlohmannJson', RAYLIB: 'raylib' };
  const depPaths = {
    ELFIO: ['elfio', 'elfio-src'], TOML11: ['toml11', 'toml11-src'], FMT: ['fmt', 'fmt-src'],
    LIBDWARF: ['libdwarf', 'libdwarf-src'], RABBITIZER: ['rabbitizer', 'rabbitizer-src'],
    NLOHMANN_JSON: ['nlohmann-json', 'nlohmann_json-src'], RAYLIB: ['raylib', 'raylib-src']
  };
  for (const [cmakeName, [checkoutName, buildName]] of Object.entries(depPaths)) {
    const candidates = [path.join(REPO_ROOT, '.upstream/dependencies', checkoutName), path.join(source, 'build/_deps', buildName)];
    const dir = candidates.find(candidate => existsSync(candidate));
    need(dir, `Pinned PS2Recomp build dependency ${cmakeName} is unavailable`, { candidates, remediation: 'Check out immutable revisions from DEPENDENCY_LOCK.json under .upstream/dependencies.' });
    const item = lock.ps2recompBuildDependencies[depLockKeys[cmakeName]];
    if (item) {
      const revision = (await run('git', ['-C', dir, 'rev-parse', 'HEAD'])).stdout.trim();
      need(revision === item.resolvedRevision, `PS2Recomp dependency ${cmakeName} revision does not match the lock`, { expected: item.resolvedRevision, actual: revision, directory: dir });
    }
    depDirs[cmakeName] = dir;
  }
  const buildDir = path.join(result.workspace, 'native-build'), binaryDir = path.join(result.workspace, 'output');
  const hook = path.join(REPO_ROOT, 'tooling/attach-recompiled.cmake');
  const hookSha256 = await hashFile(hook);
  const cmakeArgs = ['-S', source, '-B', buildDir,
    '-DPS2X_BUILD_RECOMP=OFF', '-DPS2X_BUILD_RUNTIME=ON', '-DPS2X_BUILD_ANALYZER=OFF', '-DPS2X_BUILD_TEST=OFF', '-DPS2X_BUILD_STUDIO=OFF',
    '-DPS2X_ENABLE_DEBUG_UI=OFF', '-DPS2X_ENABLE_FFMPEG=OFF', '-DPS2X_ENABLE_RUNNER_PCH=OFF', '-DPS2X_ENABLE_RUNNER_UNITY_BUILD=OFF', '-DCMAKE_BUILD_TYPE=Release',
    `-DREA_PS2_GENERATED_DIR=${result.translatedSource}`, `-DREA_PS2_NATIVE_OUTPUT=${binaryDir}`, `-DCMAKE_PROJECT_INCLUDE=${hook}`];
  for (const [name, dir] of Object.entries(depDirs)) cmakeArgs.push(`-DFETCHCONTENT_SOURCE_DIR_${name}=${dir}`);
  const markerPath = path.join(buildDir, 'stage.json');
  await mkdir(buildDir, { recursive: true });
  try {
    await run('cmake', cmakeArgs);
    const cachePath = path.join(buildDir, 'CMakeCache.txt'), cacheHash = await hashFile(cachePath);
    const configurationHash = createHash('sha256').update(JSON.stringify({ sourceRevision, generatedCode: result.outputSha256, hookSha256, depDirs, options: cmakeArgs })).digest('hex');
    const executable = process.platform === 'win32' ? path.join(binaryDir, 'Release', 'ps2EntryRunner.exe') : path.join(binaryDir, 'ps2EntryRunner');
    let previous = null;
    try { if (await exists(markerPath)) previous = JSON.parse(await readFile(markerPath, 'utf8')); } catch { /* corrupt stage marker is a cache miss */ }
    if (previous?.configurationHash === configurationHash && previous.cacheHash === cacheHash && previous.executableSha256 === await hashFile(executable))
      return { ...result, status: 'native_build_complete_unverified', nativeBuildCache: 'hit', executable, executableSha256: previous.executableSha256, blockers: ['Native runner compiled and linked; execution behavior remains unverified.', 'No independent reference comparison or playability scenario has passed.'] };
    await run('cmake', ['--build', buildDir, '--config', 'Release', '--target', 'ps2EntryRunner', '--parallel', '4']);
    need(await exists(executable), 'CMake reported success but native runner executable is missing', { executable });
    const executableSha256 = await hashFile(executable);
    await writeJsonAtomic(markerPath, { schemaVersion: 1, sourceRevision, generatedCode: result.outputSha256, configurationHash, cacheHash, executableSha256, executableSize: (await stat(executable)).size, completedAt: new Date().toISOString() });
    return { ...result, status: 'native_build_complete_unverified', nativeBuildCache: 'miss', executable, executableSha256, blockers: ['Native runner compiled and linked; execution behavior remains unverified.', 'No independent reference comparison or playability scenario has passed.'] };
  } catch (error) {
    throw new ReaError('BUILD_FAILURE', 'PS2Recomp runtime configuration or native runner build failed', { exitCode: error.code, stderr: String(error.stderr || '').slice(-4096), stdout: String(error.stdout || '').slice(-4096), message: error.message, buildDirectory: buildDir });
  }
}

async function hashFiles(directory, names) {
  const hash = createHash('sha256');
  need(names.length <= 100000, 'Generated output has too many files to validate', { count: names.length });
  let total = 0;
  for (const name of [...names].sort()) {
    const full = path.join(directory, name), metadata = await stat(full); if (!metadata.isFile()) continue;
    total += metadata.size; need(total <= 8 * 1024 ** 3, 'Generated output exceeds the 8 GiB validation limit', { bytes: total });
    hash.update(name).update('\0');
    for await (const chunk of createReadStream(full)) hash.update(chunk);
  }
  return hash.digest('hex');
}

async function hashFile(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

async function writeJsonAtomic(file, value) {
  const temporary = `${file}.${process.pid}.tmp`; await writeFile(temporary, JSON.stringify(value, null, 2)); await rename(temporary, file);
}

async function main(argv) {
  const [command, ...args] = argv, json = args.includes('--json'); let result;
  if (command === 'doctor') result = await doctor();
  else if (command === 'inspect') { need(args[0] && !args[0].startsWith('--'), 'Usage: rea-ps2 inspect <input> [--json]'); result = await inspect(args[0]); }
  else if (['analyze', 'recompile', 'run'].includes(command)) {
    need(args[0] && !args[0].startsWith('--'), `Usage: rea-ps2 ${command} <input> [--json]`);
    const input = await inspect(args[0]);
    if (command === 'analyze') result = await runAnalyzer(input, args);
    else if (command === 'recompile') result = await runRecompiler(input, args);
    else result = await launchNative(input, args);
  } else if (command === 'help' || !command) { result = { usage: ['rea-ps2 doctor [--json]', 'rea-ps2 inspect <input> [--json]', 'rea-ps2 analyze <input> [--json]', 'rea-ps2 recompile <input> [--json]', 'rea-ps2 run <input> [--timeout-ms <100..86400000>] [--json]'] }; }
  else throw new ReaError('INVALID_INPUT', `Unknown command: ${command}`);
  process.stdout.write(json ? JSON.stringify(result, null, 2) + '\n' : `${JSON.stringify(result, null, 2)}\n`);
  return command === 'recompile' ? EXIT.unsupported : EXIT.success;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }).catch(error => {
    const payload = { schemaVersion: 1, status: 'error', error: { code: error.code ?? 'INTERNAL_ERROR', message: error.message, details: error.details ?? {} } };
    process.stderr.write(JSON.stringify(payload) + '\n'); process.exitCode = error.code === 'INVALID_INPUT' ? EXIT.invalidInput : error.code === 'PREREQUISITE_MISSING' ? EXIT.prerequisite : error.code === 'UNSUPPORTED_TARGET' ? EXIT.unsupported : error.code === 'ANALYSIS_FAILURE' ? EXIT.analysis : error.code === 'BUILD_FAILURE' ? EXIT.compile : error.code === 'RUNTIME_FAILURE' ? EXIT.runtime : error.code === 'CANCELLED' ? EXIT.cancelled : error.code === 'TIMEOUT' ? EXIT.timeout : EXIT.internal;
  });
}
