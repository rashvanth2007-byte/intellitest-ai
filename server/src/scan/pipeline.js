import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';
import { getDb } from '../db/index.js';
import { newId } from '../util/crypto.js';
import { prepareSource } from '../ingest/prepare.js';
import { walk } from '../ingest/walker.js';
import { runRules } from '../engines/rules/index.js';
import { runSecrets, maskAll } from '../engines/secrets.js';
import { runDeps } from '../engines/deps.js';
import { buildChunks } from '../engines/ai/chunker.js';
import { runAgents, AGENTS } from '../engines/ai/agents.js';
import { normalizeFinding, dedupe, countBySeverity, scoreOf, sortFindings } from './normalize.js';
import { publish } from './events.js';
import { getSettings, resolveEngine, resolveGithubToken } from '../settings/service.js';

/** Execute one scan end-to-end. `job` = { id, userId, source, workDir, controller }. */
export async function runScan(job) {
  const db = getDb();
  const t0 = Date.now();
  const signal = job.controller.signal;
  const settings = await getSettings(job.userId);
  const engine = await resolveEngine(job.userId, settings);
  const enabledAgents = settings.agents;

  const progress = {
    stage: 'ingest',
    message: 'Preparing source…',
    stages: { ingest: 'running', rules: 'pending', secrets: 'pending', deps: 'pending', ai: engine.provider ? 'pending' : 'skipped' },
    agents: Object.fromEntries(AGENTS.map((a) => [a.id, { status: enabledAgents.includes(a.id) ? 'idle' : 'off', static: 0, ai: 0 }])),
    engine: engine.provider ? `${engine.provider}:${engine.model}` : 'rules',
    files: 0,
    lines: 0,
  };
  const warnings = [];
  if (!engine.provider) {
    warnings.push(engine.missing
      ? `No ${engine.missing === 'claude' ? 'Anthropic' : 'Gemini'} API key configured — AI agents were skipped. Set ${engine.missing === 'claude' ? 'ANTHROPIC_API_KEY' : 'GEMINI_API_KEY'} in the server .env file.`
      : 'AI agents skipped (no API key configured). Rule, secret and dependency engines still ran.');
  }
  let lastSave = 0;
  const emit = async (force = false) => {
    publish(job.id, 'progress', progress);
    if (force || Date.now() - lastSave > 1500) {
      lastSave = Date.now();
      await db.run('UPDATE scans SET progress = ? WHERE id = ?', [JSON.stringify(progress), job.id]);
    }
  };
  const checkAbort = () => { if (signal.aborted) throw Object.assign(new Error('Scan cancelled'), { name: 'AbortError' }); };

  await db.run("UPDATE scans SET status = 'running', engine = ?, ai_model = ? WHERE id = ?", [engine.provider || 'rules', engine.model || null, job.id]);
  await emit(true);

  /* 1. Ingest */
  const github = job.source.kind === 'github' ? await resolveGithubToken(job.userId) : {};
  const { srcDir, meta } = await prepareSource(job.source, job.workDir, {
    githubToken: github.token, githubTokenShared: github.shared, signal, onStatus: (m) => { progress.message = m; emit().catch(() => {}); },
  });
  checkAbort();
  if (meta.github) {
    await db.run('UPDATE scans SET source_ref = ? WHERE id = ?', [`${meta.github.fullName}@${meta.github.ref}${meta.github.subdir ? `/${meta.github.subdir}` : ''}`, job.id]);
  }
  const { files, skipped } = walk(srcDir, config.limits);
  if (!files.length) throw Object.assign(new Error('No readable source files were found in the input.'), { userFacing: true });
  const fileMap = new Map(files.map((f) => [f.path, f]));
  progress.files = files.length;
  progress.lines = files.reduce((n, f) => n + (f.minified ? 0 : f.content.split('\n').length), 0);
  if (skipped.large) warnings.push(`${skipped.large} file(s) larger than ${Math.round(config.limits.maxFileBytes / 1024)} KB were skipped.`);
  progress.stages.ingest = 'done';

  /* 2. Static engines */
  const all = [];
  const addFindings = (list) => {
    const norm = list.map((f) => normalizeFinding(f, fileMap)).filter(Boolean);
    all.push(...norm);
    for (const f of norm) {
      const a = progress.agents[f.agent];
      if (a) f.engine === 'ai' ? a.ai++ : a.static++;
    }
    if (norm.length) publish(job.id, 'findings', norm);
    return norm;
  };

  progress.stage = 'rules'; progress.stages.rules = 'running'; progress.message = `Running ${files.length} files through the rule engine…`;
  await emit();
  const ruleFindings = addFindings(runRules(files));
  progress.stages.rules = 'done';

  progress.stage = 'secrets'; progress.stages.secrets = 'running'; progress.message = 'Searching for exposed secrets…';
  await emit();
  const secretHits = runSecrets(files);
  const secretValues = secretHits.values;
  addFindings(secretHits);
  progress.stages.secrets = 'done';
  checkAbort();

  progress.stage = 'deps'; progress.stages.deps = 'running'; progress.message = 'Checking dependencies against OSV.dev…';
  await emit();
  const deps = await runDeps(files, { enabled: config.osvEnabled, signal });
  addFindings(deps.findings);
  warnings.push(...deps.warnings);
  progress.depStats = deps.stats;
  progress.stages.deps = deps.stats.packages ? 'done' : 'skipped';
  checkAbort();

  /* 3. AI agents */
  let usage = null;
  if (engine.provider) {
    // Secrets already found are redacted before code is sent to the AI provider.
    const aiFiles = secretValues.length ? files.map((f) => ({ ...f, content: maskAll(f.content, secretValues) })) : files;
    const plan = buildChunks(aiFiles, ruleFindings, settings.aiDepth);
    progress.ai = { chunks: plan.chunks.length, filesIncluded: plan.included, filesEligible: plan.eligible };
    if (!plan.chunks.length) {
      progress.stages.ai = 'skipped';
    } else {
      if (plan.included < plan.eligible) warnings.push(`AI agents reviewed the ${plan.included} most security-relevant of ${plan.eligible} code files (depth: ${settings.aiDepth}). Increase AI depth in Settings for wider coverage.`);
      progress.stage = 'ai'; progress.stages.ai = 'running';
      progress.message = `${plan.chunks.length > 1 ? `${plan.chunks.length} parts × ` : ''}${enabledAgents.length} agents analysing with ${engine.model}…`;
      await emit(true);
      try {
        const res = await runAgents({
          chunks: plan.chunks, provider: engine.provider, apiKey: engine.apiKey, model: engine.model,
          agentIds: enabledAgents, ruleFindings, signal,
          onAgent: (id, status, payload) => {
            const a = progress.agents[id];
            if (!a) return;
            if (status !== 'progress') a.status = status;
            if (payload?.findings) addFindings(payload.findings);
            if (payload?.message) a.message = payload.message;
            emit().catch(() => {}); // fire-and-forget: a failed progress save must not crash the process
          },
        });
        usage = res.usage;
        warnings.push(...res.warnings);
        progress.stages.ai = 'done';
      } catch (e) {
        if (e.name === 'AbortError' || signal.aborted) throw e;
        warnings.push(`AI agents failed: ${e.message}`);
        progress.stages.ai = 'error';
      }
    }
  }
  for (const a of Object.values(progress.agents)) if (a.status === 'idle') a.status = 'complete';

  /* 4. Merge, score, persist */
  checkAbort(); // a cancel during the AI stage must not end up recorded as "completed"
  progress.stage = 'report'; progress.message = 'Building report…';
  await emit(true);
  const final = sortFindings(dedupe(all));
  if (secretValues.length) {
    for (const f of final) {
      if (f.snippet) f.snippet = f.snippet.map((l) => ({ n: l.n, t: maskAll(l.t, secretValues) }));
      f.description = maskAll(f.description, secretValues);
      f.recommendation = maskAll(f.recommendation, secretValues);
    }
  }
  const counts = countBySeverity(final);
  const { score, grade } = scoreOf(final);
  const now = Date.now();
  await db.tx(async (t) => {
    await t.run('DELETE FROM findings WHERE scan_id = ?', [job.id]);
    for (const f of final) {
      await t.run(
        `INSERT INTO findings (id, scan_id, user_id, severity, title, category, cwe, owasp, cvss, file, line, snippet, description, impact, recommendation, engines, agent, rule_id, confidence, extra, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [newId(), job.id, job.userId, f.severity, f.title, f.category, f.cwe, f.owasp, f.cvss, f.file, f.line,
          f.snippet ? JSON.stringify(f.snippet) : null, f.description, f.impact, f.recommendation, f.engines.join(','),
          f.agent, f.ruleId, f.confidence, f.extra ? JSON.stringify(f.extra) : null, now],
      );
    }
    progress.stage = 'done';
    progress.message = `${final.length} issue${final.length === 1 ? '' : 's'} found`;
    progress.usage = usage;
    await t.run(
      `UPDATE scans SET status = 'completed', counts = ?, total = ?, score = ?, grade = ?, files_scanned = ?, lines_scanned = ?,
       warnings = ?, progress = ?, duration_ms = ?, finished_at = ? WHERE id = ?`,
      [JSON.stringify(counts), final.length, score, grade, files.length, progress.lines, JSON.stringify(warnings),
        JSON.stringify(progress), now - t0, now, job.id],
    );
  });
  publish(job.id, 'progress', progress);
}

export function cleanupWorkDir(workDir) {
  try { fs.rmSync(workDir, { recursive: true, force: true, maxRetries: 3 }); } catch (e) { console.warn('[scan] cleanup failed', workDir, e.message); }
}

export function workDirFor(scanId) {
  return path.join(config.tmpDir, `scan-${scanId}`);
}
