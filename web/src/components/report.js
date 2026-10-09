import { getFix, langName } from '../lib/fixes.js';
import { esc, icon, SEVS, SEV_VAR, AGENT_META, ENGINE_LABEL, fmtDate, fmtNum, fmtDuration, gradeColor, modal, safeUrl } from '../lib/ui.js';

/** Grade ring SVG. */
export function gradeRing(score, grade) {
  const r = 40, c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score ?? 0)) / 100;
  return `<div class="grade" title="Security score ${score ?? '–'}/100">
    <svg viewBox="0 0 92 92"><circle cx="46" cy="46" r="${r}" fill="none" stroke="var(--border)" stroke-width="7"/>
    <circle cx="46" cy="46" r="${r}" fill="none" stroke="${gradeColor(grade)}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${c * pct} ${c}"/></svg>
    <div class="g"><div><b style="color:${gradeColor(grade)}">${esc(grade || '–')}</b><span>${esc(score ?? "–")}/100</span></div></div>
  </div>`;
}

export function statsStrip(counts, total) {
  return `<div class="stats-strip">
    ${SEVS.map((s) => `<div class="stat"><div class="stat-sq" style="background:${SEV_VAR[s]}"></div><div><div class="s-num" style="color:${SEV_VAR[s]}">${esc(counts?.[s] || 0)}</div><div class="s-lbl">${s}</div></div></div>`).join('')}
    <div class="stat"><div class="stat-sq" style="background:var(--text-dim)"></div><div><div class="s-num">${esc(total)}</div><div class="s-lbl">total</div></div></div>
  </div>`;
}

/** Stable identity for a finding, so open/closed state survives list re-renders. */
export function findingKey(f) {
  const raw = [f.file, f.line, f.title, f.ruleId, f.agent, f.extra?.package].map((x) => String(x ?? '')).join('|');
  let h = 5381;
  for (let i = 0; i < raw.length; i++) h = ((h * 33) ^ raw.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

export function findingCard(f, uid, key = '', open = false) {
  const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : (f.category || '');
  const sev = esc(f.severity);
  const advUrl = safeUrl(f.extra?.url);
  return `<div class="vc ${sev}${open ? ' open' : ''}" id="${uid}" data-key="${esc(key)}">
    <button class="vc-head" type="button" aria-expanded="${open}" aria-controls="${uid}-b">
      <span class="badge ${sev}">${sev.toUpperCase()}</span>
      <span class="vc-title"><b>${esc(f.title)}</b><span>${esc(f.file || f.category || '')}</span></span>
      <span class="vc-meta">
        ${f.line ? `<span class="line-pill" title="Error is on line ${esc(f.line)}">Line ${esc(f.line)}</span>` : ''}
        ${f.cvss != null && Number.isFinite(Number(f.cvss)) ? `<span class="cvss-pill">CVSS ${Number(f.cvss).toFixed(1)}</span>` : ''}
        <span class="tag">${esc(AGENT_META[f.agent]?.name || f.agent)}</span>
        ${icon('chevron', 'chev')}
      </span>
    </button>
    <div class="vc-body" id="${uid}-b">
      <div class="vc-tags">
        ${f.file ? `<span class="tag" style="color:var(--accent)">${esc(loc)}</span>` : ''}
        ${f.cwe ? (/^CWE-\d+$/.test(String(f.cwe)) ? `<a class="tag" href="https://cwe.mitre.org/data/definitions/${String(f.cwe).slice(4)}.html" target="_blank" rel="noopener noreferrer">${esc(f.cwe)}</a>` : `<span class="tag">${esc(f.cwe)}</span>`) : ''}
        ${f.owasp ? `<span class="tag">OWASP ${esc(f.owasp)}</span>` : ''}
        ${f.category ? `<span class="tag">${esc(f.category)}</span>` : ''}
        ${(f.engines || []).map((e) => `<span class="badge ${e === 'ai' ? 'accent' : 'neutral'}">${esc(ENGINE_LABEL[e] || e)}</span>`).join('')}
        <span class="badge neutral">confidence: ${esc(f.confidence || 'medium')}</span>
      </div>
      ${f.file ? `<div class="err-loc">${icon('alert')}<div><b>Error location</b><span><code>${esc(f.file)}</code>${f.line ? ` — line <b>${esc(f.line)}</b>` : ''}</span></div></div>` : ''}
      ${Array.isArray(f.snippet) && f.snippet.length ? `<div class="snippet" role="figure" aria-label="Code around line ${esc(f.line)}">${f.snippet.map((s) => `<div class="${s?.n === f.line ? 'hl' : ''}"><span class="mk">${s?.n === f.line ? '▶' : ''}</span><span class="n">${esc(s?.n)}</span><span>${esc(s?.t)}</span></div>`).join('')}</div>` : ''}
      ${f.description ? `<div class="vc-detail"><strong>Description</strong>${esc(f.description)}</div>` : ''}
      ${f.impact ? `<div class="vc-detail"><strong>Impact</strong>${esc(f.impact)}</div>` : ''}
      ${fixPanel(f, uid)}
      ${advUrl ? `<div class="vc-detail"><a href="${esc(advUrl)}" target="_blank" rel="noopener noreferrer">${esc(f.extra.advisory || f.extra.cve || 'Advisory')}${f.extra.cve && f.extra.cve !== f.extra.advisory ? ` / ${esc(f.extra.cve)}` : ''} ${icon('external', 'chev')}</a>${Array.isArray(f.extra.fixed) && f.extra.fixed.length ? ` · fixed in ${esc(f.extra.fixed.join(', '))}` : ''}</div>` : ''}
    </div>
  </div>`;
}

/** Collapsible "How to fix" bar: recommendation, step-by-step suggestions and a safe-code example. */
function fixPanel(f, uid) {
  const fix = getFix(f);
  const steps = fix.steps || [];
  const count = steps.length + (f.recommendation ? 1 : 0) + (fix.example ? 1 : 0) + (fix.commands?.length ? 1 : 0);
  if (!count) return '';
  const errLine = Array.isArray(f.snippet) ? f.snippet.find((s) => s?.n === f.line)?.t : null;
  return `<div class="fix-wrap">
    <button class="fix-toggle" type="button" aria-expanded="false" aria-controls="${uid}-fix">
      <span class="fix-ico" aria-hidden="true">💡</span><span>How to fix this</span><span class="fix-count">${count} suggestion${count > 1 ? 's' : ''}</span>${icon('chevron', 'chev')}
    </button>
    <div class="fix-panel" id="${uid}-fix">
      ${f.recommendation ? `<div class="fix-sec"><strong>Recommended fix</strong><div class="vc-detail">${esc(f.recommendation)}</div></div>` : ''}
      ${steps.length ? `<div class="fix-sec"><strong>Steps</strong><ol>${steps.map((x) => `<li>${esc(x)}</li>`).join('')}</ol></div>` : ''}
      ${fix.commands?.length ? `<div class="fix-sec"><strong>Run</strong><pre class="code-ex">${esc(fix.commands.join('\n'))}</pre><button class="btn btn-ghost btn-sm copy-btn" type="button" data-copy="${esc(fix.commands[0])}">Copy command</button></div>` : ''}
      ${fix.example ? `<div class="fix-sec">
        ${errLine != null ? `<strong>Your code (line ${esc(f.line)})</strong><pre class="code-ex bad">${esc(String(errLine).trim())}</pre>` : ''}
        <strong>Safer version${fix.example.sameLanguage ? '' : ` (example in ${esc(langName(fix.example.lang))})`}</strong>
        <pre class="code-ex good">${esc(fix.example.code)}</pre>
        <button class="btn btn-ghost btn-sm copy-btn" type="button" data-copy="${esc(fix.example.code)}">Copy example</button>
      </div>` : ''}
    </div>
  </div>`;
}

/** Delegate expand/collapse for any container of finding cards; records open cards in openSet. */
export function wireCards(container, openSet = null) {
  container.addEventListener('click', (e) => {
    const toggle = e.target.closest('.fix-toggle');
    if (toggle && container.contains(toggle)) {
      const open = toggle.parentElement.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
      return;
    }
    const copy = e.target.closest('.copy-btn');
    if (copy && container.contains(copy)) {
      navigator.clipboard?.writeText(copy.dataset.copy || '').then(() => {
        const t = copy.textContent; copy.textContent = 'Copied ✓'; setTimeout(() => { copy.textContent = t; }, 1500);
      }).catch(() => {});
      return;
    }
    const head = e.target.closest('.vc-head');
    if (!head || !container.contains(head)) return;
    const card = head.parentElement;
    const open = card.classList.toggle('open');
    head.setAttribute('aria-expanded', String(open));
    if (openSet && card.dataset.key) open ? openSet.add(card.dataset.key) : openSet.delete(card.dataset.key);
  });
}

/** Set the open state of every card in a container (and in openSet). */
export function setAllCards(container, open, openSet = null) {
  container.querySelectorAll('.vc').forEach((c) => {
    c.classList.toggle('open', open);
    c.querySelector('.vc-head')?.setAttribute('aria-expanded', String(open));
    if (openSet && c.dataset.key) open ? openSet.add(c.dataset.key) : openSet.delete(c.dataset.key);
  });
}

/**
 * Grouped finding list (used live while scanning and in the final report).
 * Cards are keyed by a stable hash of file/line/title/rule, so cards listed in openSet stay expanded across re-renders.
 */
export function findingList(findings, prefix = 'f', openSet = null) {
  if (!findings.length) return '';
  let h = '';
  const seen = new Map();
  for (const s of SEVS) {
    const grp = findings.filter((f) => f.severity === s);
    if (!grp.length) continue;
    h += `<div class="sec-hdr"><h3 style="color:${SEV_VAR[s]}">${s.toUpperCase()} — ${grp.length}</h3><div class="ln"></div></div>`;
    h += grp.map((f) => {
      const base = findingKey(f);
      const n = seen.get(base) || 0; // identical findings get distinct, still stable, keys
      seen.set(base, n + 1);
      const key = n ? `${base}-${n}` : base;
      return findingCard(f, `${prefix}-${key}`, key, !!openSet?.has(key));
    }).join('');
  }
  return h;
}

/** Full interactive report for a completed scan. */
export function renderReport(root, scan, { onDelete } = {}) {
  const filters = { sev: new Set(SEVS), agent: '', engine: '', q: '' };
  const agentsPresent = [...new Set(scan.findings.map((f) => f.agent))];
  const enginesPresent = [...new Set(scan.findings.flatMap((f) => f.engines || []))];

  root.innerHTML = `
    <div class="card report-head">
      ${gradeRing(scan.score, scan.grade)}
      <div style="min-width:0">
        ${statsStrip(scan.counts, scan.total)}
        <div class="report-meta">
          <span>${icon('file', 'chev')} ${fmtNum(scan.filesScanned)} files · ${fmtNum(scan.linesScanned)} lines</span>
          <span>Engine: <b>${esc(scan.aiModel || 'rules + secrets + CVE lookup')}</b></span>
          <span>${fmtDate(scan.createdAt)}</span>
          <span>Took ${fmtDuration(scan.durationMs)}</span>
          ${safeUrl(scan.sourceRef) ? `<a href="${esc(safeUrl(scan.sourceRef))}" target="_blank" rel="noopener noreferrer">${esc(scan.sourceRef.replace('https://', ''))}</a>` : ''}
        </div>
      </div>
    </div>
    ${scan.warnings?.length ? `<div class="warnings" style="margin-top:12px">${scan.warnings.map((w) => `<div class="warning">${esc(w)}</div>`).join('')}</div>` : ''}
    <div class="btn-row" style="margin:14px 0">
      <a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(scan.id)}/report.html?inline=1" target="_blank" rel="noopener">${icon('eye')}Open HTML report</a>
      ${['html', 'json', 'sarif', 'csv'].map((f) => `<a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(scan.id)}/report.${f}" download>${icon('download')}${f.toUpperCase()}</a>`).join('')}
      ${onDelete ? `<button class="btn btn-danger btn-sm" id="delScan" style="margin-left:auto">${icon('trash')}Delete</button>` : ''}
    </div>
    ${scan.findings.length ? `
    <div class="filters" role="group" aria-label="Filters">
      ${SEVS.map((s) => `<button class="chip-toggle on" data-sev="${s}" aria-pressed="true"><i style="background:${SEV_VAR[s]}"></i>${s} ${scan.counts[s] || 0}</button>`).join('')}
      <select class="select" id="fAgent" aria-label="Agent"><option value="">All agents</option>${agentsPresent.map((a) => `<option value="${esc(a)}">${esc(AGENT_META[a]?.name || a)}</option>`).join('')}</select>
      <select class="select" id="fEngine" aria-label="Engine"><option value="">All engines</option>${enginesPresent.map((e) => `<option value="${esc(e)}">${esc(ENGINE_LABEL[e] || e)}</option>`).join('')}</select>
      <input class="input" id="fQ" type="search" placeholder="Search title, file, CWE…" aria-label="Search findings">
    </div>
    <div class="btn-row" style="margin-bottom:6px"><button class="btn btn-ghost btn-sm" id="expandAll">Expand all</button><span class="dim" id="shownCount" style="font-size:11.5px;align-self:center"></span></div>
    <div id="fList"></div>` : `<div class="card empty-state">${icon('check')}<h3>No issues found</h3><p>None of the engines reported a problem. Automated tools can miss issues — keep reviewing security-sensitive code.</p></div>`}
  `;

  const list = root.querySelector('#fList');
  if (list) {
    const openSet = new Set();
    wireCards(list, openSet);
    const apply = () => {
      const q = filters.q.toLowerCase();
      const shown = scan.findings.filter((f) => filters.sev.has(f.severity)
        && (!filters.agent || f.agent === filters.agent)
        && (!filters.engine || (f.engines || []).includes(filters.engine))
        && (!q || `${f.title} ${f.file} ${f.cwe} ${f.category} ${f.description}`.toLowerCase().includes(q)));
      list.innerHTML = findingList(shown, 'r', openSet) || '<div class="empty-state"><p>No findings match these filters.</p></div>';
      root.querySelector('#shownCount').textContent = `${shown.length} of ${scan.findings.length} shown`;
      const cards = list.querySelectorAll('.vc');
      root.querySelector('#expandAll').textContent = cards.length && [...cards].every((c) => c.classList.contains('open')) ? 'Collapse all' : 'Expand all';
    };
    root.querySelectorAll('[data-sev]').forEach((b) => b.addEventListener('click', () => {
      const s = b.dataset.sev;
      filters.sev.has(s) ? filters.sev.delete(s) : filters.sev.add(s);
      b.classList.toggle('on', filters.sev.has(s));
      b.setAttribute('aria-pressed', String(filters.sev.has(s)));
      apply();
    }));
    root.querySelector('#fAgent').onchange = (e) => { filters.agent = e.target.value; apply(); };
    root.querySelector('#fEngine').onchange = (e) => { filters.engine = e.target.value; apply(); };
    root.querySelector('#fQ').oninput = (e) => { filters.q = e.target.value; apply(); };
    root.querySelector('#expandAll').onclick = (e) => {
      const btn = e.currentTarget;
      const open = btn.textContent === 'Expand all';
      setAllCards(list, open, openSet);
      btn.textContent = open ? 'Collapse all' : 'Expand all';
    };
    apply();
  }
  root.querySelector('#delScan')?.addEventListener('click', onDelete);
}

/** Alert popup for serious findings, honouring the user's threshold (all findings considered). */
export function maybeAlert(scan, threshold) {
  if (threshold === 'off') return;
  const hits = scan.findings.filter((f) => f.severity === 'critical' || (threshold === 'high' && f.severity === 'high'));
  if (!hits.length) return;
  modal({
    title: `<span style="color:var(--critical)">${hits.length} ${threshold === 'high' ? 'critical/high' : 'critical'} issue${hits.length > 1 ? 's' : ''} found</span>`,
    body: `<p class="muted" style="margin-bottom:12px">These are likely exploitable — review them first.</p>
      <div style="display:flex;flex-direction:column;gap:8px">${hits.slice(0, 6).map((v) => `
        <div style="padding:10px 12px;background:color-mix(in srgb,var(--critical) 8%,transparent);border:1px solid color-mix(in srgb,var(--critical) 25%,transparent);border-radius:8px">
          <b style="display:block;font-size:12.5px;margin-bottom:3px">${esc(v.title)}</b>
          <span class="mono dim" style="font-size:11px">${esc(v.file || '')}${v.line ? `:${esc(v.line)}` : ''}${v.cwe ? ` · ${esc(v.cwe)}` : ''} · CVSS ${esc(v.cvss ?? '–')}</span>
        </div>`).join('')}${hits.length > 6 ? `<div class="dim" style="font-size:12px">…and ${hits.length - 6} more</div>` : ''}</div>`,
    buttons: [{ label: 'Review findings', value: true, cls: 'btn-primary' }],
  });
}
