import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const analyzer = process.env.REA_PS2_ANALYZER;
const recompiler = process.env.REA_PS2_RECOMP;
const recompilerSource = process.env.REA_PS2RECOMP_SOURCE;
assert.ok(analyzer, 'REA_PS2_ANALYZER must identify the real pinned ps2_analyzer executable');
assert.ok(recompiler, 'REA_PS2_RECOMP must identify the real pinned ps2_recomp executable');
assert.ok(recompilerSource, 'REA_PS2RECOMP_SOURCE must identify the pinned PS2Recomp source checkout');
const temp = await mkdtemp(path.join(os.tmpdir(), 'rea-ps2-upstream-'));
try {
  const elf = path.join(temp, 'synthetic-mips.elf');
  await promisify(execFile)(process.execPath, [path.join(root, 'tooling/create-minimal-mips-elf.js'), elf]);
  const commonEnv = { ...process.env, REA_PS2_ANALYZER: analyzer, REA_PS2_RECOMP: recompiler, REA_PS2RECOMP_SOURCE: recompilerSource };
  const run = async () => {
    let stdout, exitCode = 0;
    try { ({ stdout } = await promisify(execFile)(process.execPath, [path.join(root, 'apps/cli/src/main.js'), 'recompile', elf, '--json', '--workspace', path.join(temp, 'workspace')], { cwd: root, env: commonEnv, timeout: 30 * 60 * 1000, windowsHide: true })); }
    catch (error) { if (error.code !== 4) throw error; stdout = error.stdout; exitCode = 4; }
    const result = JSON.parse(stdout); result.exitCode = exitCode; return result;
  };
  const cold = await run();
  assert.equal(cold.status, 'native_build_complete_unverified');
  assert.equal(cold.exitCode, 4, 'the CLI must preserve unsupported status until execution and behavioral verification exist');
  assert.equal(cold.translatedFunctions, 1);
  assert.equal(cold.unhandledInstructions, 0);
  assert.equal(cold.nativeBuildCache, 'miss');
  assert.ok(cold.executableSha256);
  assert.ok((await stat(cold.executable)).size > 0, 'compiled native runner must exist');
  const files = await readdir(cold.translatedSource);
  assert.ok(files.includes('register_functions.cpp'), 'generated function registration must exist');
  const translated = await Promise.all(files.filter(f => f.endsWith('.cpp')).map(f => readFile(path.join(cold.translatedSource, f), 'utf8')));
  assert.ok(translated.some(s => s.includes('0x2402002a') && s.includes('SET_GPR_S32')), 'native output must contain translated guest instruction and register write');
  const warm = await run();
  assert.equal(warm.cache, 'hit');
  assert.equal(warm.translationCache, 'hit');
  assert.equal(warm.nativeBuildCache, 'hit');
  assert.equal(warm.outputSha256, cold.outputSha256);
  assert.equal(warm.executableSha256, cold.executableSha256);
  process.stdout.write(JSON.stringify({ status: 'passed', coldAnalysisCache: cold.cache, coldTranslationCache: cold.translationCache, coldNativeBuildCache: cold.nativeBuildCache, warmAnalysisCache: warm.cache, warmTranslationCache: warm.translationCache, warmNativeBuildCache: warm.nativeBuildCache, translatedFunctions: cold.translatedFunctions, unhandledInstructions: cold.unhandledInstructions, outputSha256: cold.outputSha256, executableSha256: cold.executableSha256, qualification: 'synthetic instruction, translation, native compilation and linking; no executable launch or playability claim' }, null, 2) + '\n');
} finally {
  await rm(temp, { recursive: true, force: true });
}
