import { get } from '../lib/api.js';
import { esc, icon, SEVS, SEV_VAR, fmtTime, fmtNum, gradeColor } from '../lib/ui.js';

function trendChart(points) {
  if (points.length < 2) return '<div class="dim" style="font-size:12px;padding:30px 0;text-align:center">Run a few scans to see your score trend.</div>';
  const W = 600, H = 120, pad = 8;
  const x = (i) => pad + (i * (W - pad * 2)) / (points.length - 1);
  const y = (s) => H - pad - (s / 100) * (H - pad * 2);
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Security score over recent scans">
    ${[25, 50, 75].map((g) => `<line x1="0" x2="${W}" y1="${y(g)}" y2="${y(g)}" stroke="var(--border)" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>`).join('')}
    <path d="${line} L${x(points.length - 1)},${H} L${x(0)},${H} Z" fill="var(--accent-low)"/>
    <path d="${line}" fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke"/>
    ${points.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.score)}" r="3" fill="var(--accent)"><title>${esc(p.label)}: ${esc(p.score)}/100</title></circle>`).join('')}
  </svg>`;
}

export async function renderDashboard(root) {
  root.innerHTML = '<div class="page"><div class="spinner"></div></div>';
  const s = await get('/scans/stats');
  const maxSev = Math.max(1, ...Object.values(s.totals));
  const maxCat = Math.max(1, ...s.topCategories.map((c) => c.count));
  const engines = Object.entries(s.byEngine);
  const maxEng = Math.max(1, ...engines.map(([, n]) => n));
  const engLabel = { rules: 'Rule engine', secrets: 'Secret scanner', deps: 'Dependency CVEs', ai: 'AI agents' };

  root.innerHTML = `<div class="page">
    <div class="page-head"><div><div class="page-title">Dashboard</div><div class="page-sub">Overview of every scan on your account.</div></div>
      <a class="btn btn-primary btn-sm" href="#/scanner">${icon('scan')}New scan</a></div>
    <div class="kpi-grid">
      <div class="card"><div class="kpi-lbl">Total scans</div><div class="kpi-val">${fmtNum(s.scans)}</div><div class="kpi-sub">${fmtNum(s.completed)} completed</div></div>
      <div class="card"><div class="kpi-lbl">Issues found</div><div class="kpi-val">${fmtNum(s.findings)}</div><div class="kpi-sub">Across all scans</div></div>
      <div class="card"><div class="kpi-lbl">Critical issues</div><div class="kpi-val" style="color:var(--critical)">${fmtNum(s.totals.critical)}</div><div class="kpi-sub">Need immediate fix</div></div>
      <div class="card"><div class="kpi-lbl">Average score</div><div class="kpi-val">${s.avgScore ?? '—'}<span class="dim" style="font-size:14px">${s.avgScore != null ? '/100' : ''}</span></div><div class="kpi-sub">${s.recent[0] ? `Last scan ${fmtTime(s.recent[0].at)}` : 'Run your first scan'}</div></div>
    </div>
    ${!s.scans ? `<div class="card empty-state">${icon('dashboard')}<h3>No data yet</h3><p>Your statistics appear here after the first scan.</p><a class="btn btn-primary btn-sm" href="#/scanner">Start scanning</a></div>` : `
    <div class="dash-grid">
      <div style="display:flex;flex-direction:column;gap:16px">
        <div class="card"><div class="sect-title">Score trend</div><div class="trend">${trendChart(s.trend)}</div></div>
        <div class="card"><div class="sect-title">Severity breakdown</div>
          ${SEVS.map((k) => `<div class="bar-row"><div class="lbl" style="text-transform:capitalize">${k}</div><div class="bar-track"><div class="bar-fill" style="width:${(s.totals[k] / maxSev) * 100}%;background:${SEV_VAR[k]}"></div></div><div class="n">${s.totals[k]}</div></div>`).join('')}
        </div>
        <div class="card"><div class="sect-title">Most common weaknesses</div>
          ${s.topCategories.length ? s.topCategories.map((c) => `<div class="bar-row"><div class="lbl" title="${esc(c.category)}">${esc(c.category)}</div><div class="bar-track"><div class="bar-fill" style="width:${(c.count / maxCat) * 100}%;background:var(--accent)"></div></div><div class="n">${c.count}</div></div>`).join('') : '<div class="dim" style="font-size:12px">No findings yet.</div>'}
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:16px">
        <div class="card"><div class="sect-title">Recent scans</div>
          ${s.recent.map((r) => `<a class="list-item" href="#/scan/${encodeURIComponent(r.id)}">
            <span class="grade-pill" style="color:${gradeColor(r.grade)}">${esc(r.grade || (r.status === 'completed' ? '–' : '…'))}</span>
            <span class="li-name">${esc(r.label)}</span><span class="li-time">${r.status === 'completed' ? `${esc(r.total)} issues · ` : `${esc(r.status)} · `}${fmtTime(r.at)}</span></a>`).join('')}
          <a href="#/history" style="font-size:12px;display:block;margin-top:10px">View all →</a>
        </div>
        <div class="card"><div class="sect-title">Findings by engine</div>
          ${engines.length ? engines.map(([k, n]) => `<div class="bar-row"><div class="lbl">${engLabel[k] || esc(k)}</div><div class="bar-track"><div class="bar-fill" style="width:${(n / maxEng) * 100}%;background:${k === 'ai' ? '#818CF8' : 'var(--accent)'}"></div></div><div class="n">${n}</div></div>`).join('') : '<div class="dim" style="font-size:12px">No findings yet.</div>'}
        </div>
      </div>
    </div>`}
  </div>`;
}
