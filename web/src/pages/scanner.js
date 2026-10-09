import { post, get, upload } from '../lib/api.js';
import { esc, icon, toast, fmtBytes } from '../lib/ui.js';
import { state, engineSummary } from '../main.js';
import { liveProgress, agentsRow } from '../components/live.js';
import { renderReport, maybeAlert } from '../components/report.js';

const IGNORED = /(^|\/)(node_modules|\.git|\.svn|\.hg|dist|build|\.next|\.nuxt|coverage|__pycache__|\.venv|venv|target|\.gradle|\.idea|\.vscode|\.terraform|Pods|\.dart_tool|\.cache)(\/|$)/;
const BINARY = /\.(png|jpe?g|gif|bmp|ico|webp|tiff?|psd|mp[34]|mov|avi|mkv|wav|flac|ogg|webm|rar|7z|tar|gz|tgz|bz2|xz|exe|dll|so|dylib|bin|o|a|class|pyc|wasm|pdf|docx?|xlsx?|pptx?|ttf|otf|woff2?|eot|db|sqlite3?|jar|war|apk|ipa|iso|dmg)$/i;
const MAX_TOTAL = 100 * 1024 * 1024;

const LANGS = [
  ['auto', 'Auto-detect', 'snippet.txt'], ['js', 'JavaScript / TypeScript', 'snippet.ts'], ['py', 'Python', 'snippet.py'],
  ['php', 'PHP', 'snippet.php'], ['java', 'Java / Kotlin', 'Snippet.java'], ['go', 'Go', 'snippet.go'], ['rb', 'Ruby', 'snippet.rb'],
  ['cs', 'C#', 'Snippet.cs'], ['c', 'C / C++', 'snippet.c'], ['sql', 'SQL', 'snippet.sql'], ['html', 'HTML / templates', 'snippet.html'],
  ['sh', 'Shell', 'snippet.sh'], ['docker', 'Dockerfile', 'Dockerfile'], ['yaml', 'YAML (K8s / CI)', 'snippet.yaml'], ['tf', 'Terraform', 'main.tf'],
];

function guessFilename(code) {
  if (/^\s*<\?php/.test(code)) return 'snippet.php';
  if (/^\s*FROM\s+\S+/m.test(code) && /^\s*(RUN|CMD|COPY)\s/m.test(code)) return 'Dockerfile';
  if (/\bdef\s+\w+\(.*\):|^\s*import\s+\w+\s*$|^\s*from\s+\w+\s+import\s/m.test(code)) return 'snippet.py';
  if (/\bpublic\s+(static\s+)?(class|void)\b|System\.out\./.test(code)) return 'Snippet.java';
  if (/\bpackage\s+main\b|func\s+\w+\(.*\)\s*\{/.test(code)) return 'snippet.go';
  if (/#include\s*</.test(code)) return 'snippet.c';
  if (/\busing\s+System\b|namespace\s+\w+/.test(code)) return 'Snippet.cs';
  if (/\b(const|let|var|function|=>|require\(|import\s.+from)\b/.test(code)) return 'snippet.js';
  if (/<\/?(html|div|script|body)\b/i.test(code)) return 'snippet.html';
  return 'snippet.txt';
}

/** Recursively read dropped folders (DataTransferItem.webkitGetAsEntry). */
async function readEntries(items) {
  const out = [];
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      // An unreadable file (permissions, deleted meanwhile) must not abort the whole folder.
      const file = await new Promise((res) => entry.file(res, () => res(null)));
      if (file) out.push({ file, path: prefix + file.name });
    } else if (entry.isDirectory) {
      if (IGNORED.test(prefix + entry.name + '/')) return;
      const reader = entry.createReader();
      let batch;
      do { // readEntries returns at most ~100 entries per call: keep reading until it returns none
        batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        for (const e of batch) await walk(e, `${prefix}${entry.name}/`);
      } while (batch.length);
    }
  };
  const entries = [...items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  for (const e of entries) await walk(e, '');
  return out;
}

export function renderScanner(root) {
  const eng = engineSummary();
  let tab = 'upload';
  let picked = []; // { file, path }
  let stopLive = null;
  let disposed = false;
  const gh = state.user.github;

  root.innerHTML = `<div class="page">
    <div class="page-head"><div>
      <div class="page-title">Scanner</div>
      <div class="page-sub">Upload files, a folder or a .zip, paste code, or point at a GitHub repository.</div>
    </div></div>
    <div class="scan-grid">
      <div class="input-stack">
        <div class="card" style="padding:14px;display:flex;flex-direction:column;gap:12px">
          <div class="tabs" role="tablist">
            <button class="tab active" data-tab="upload" role="tab" aria-selected="true">${icon('upload')}Upload</button>
            <button class="tab" data-tab="github" role="tab" aria-selected="false">${icon('github')}GitHub</button>
            <button class="tab" data-tab="paste" role="tab" aria-selected="false">${icon('code')}Paste</button>
          </div>

          <div data-panel="upload" style="display:flex;flex-direction:column;gap:10px">
            <div class="drop-zone" id="dropZone" tabindex="0" role="button" aria-label="Choose files to scan">
              ${icon('upload')}
              <h4>Drop files, folders or a .zip</h4>
              <p>Any source code: JS/TS, Python, PHP, Java, Go, Ruby, C#, C/C++, Rust, configs, Dockerfiles, IaC…<br>node_modules, .git and binaries are skipped automatically.</p>
            </div>
            <div class="btn-row">
              <button class="btn btn-ghost btn-sm" id="pickFiles" style="flex:1">${icon('file')}Files / .zip</button>
              <button class="btn btn-ghost btn-sm" id="pickFolder" style="flex:1">${icon('folder')}Folder</button>
            </div>
            <input type="file" id="fiFiles" multiple hidden>
            <input type="file" id="fiFolder" webkitdirectory directory multiple hidden>
            <div id="picked"></div>
          </div>

          <div data-panel="github" class="hidden" style="display:flex;flex-direction:column;gap:10px">
            <div class="field">
              <label class="field-label" for="ghUrl">Repository URL</label>
              <input class="input mono" id="ghUrl" placeholder="https://github.com/owner/repo" autocomplete="off" spellcheck="false">
            </div>
            <p class="hint">Branches and sub-folders work too: <span class="mono">…/tree/main/src</span>. Public repos need no setup.
            ${gh ? (/\brepo\b/.test(gh.scope || '') ? `Private repos accessible to <b>@${esc(gh.login)}</b> are supported.` : `To scan private repos, <a href="/api/auth/github/start?scope=repo">grant repo access</a>.`)
              : state.providers.github ? `To scan private repos, <a href="/api/auth/github/start?scope=repo">connect GitHub</a> or add a token in <a href="#/settings">Settings</a>.` : `For private repos add a GitHub token in <a href="#/settings">Settings</a>.`}</p>
          </div>

          <div data-panel="paste" class="hidden" style="display:flex;flex-direction:column;gap:10px">
            <div class="field">
              <label class="field-label" for="lang">Language</label>
              <select class="select" id="lang" style="width:100%">${LANGS.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select>
            </div>
            <textarea class="textarea" id="codeIn" placeholder="// Paste source code here…" spellcheck="false"></textarea>
          </div>

          <a class="engine-line" href="#/settings" style="text-decoration:none">
            ${icon(eng.ai ? 'sparkle' : 'alert')}
            <span><b style="color:var(--text)">${esc(eng.label)}</b>${eng.detail ? ` · ${esc(eng.detail)}` : ''}</span>
          </a>
          <div class="progress hidden" id="upProg"><div style="width:0"></div></div>
          <button class="btn btn-primary btn-block" id="analyzeBtn">${icon('scan')}Analyze</button>
        </div>
      </div>

      <div id="results">
        ${agentsRow(null)}
        <div class="card empty-state" id="emptyState">
          ${icon('shield')}
          <h3>Ready to analyze</h3>
          <p>The rule engine, secret scanner and CVE lookup always run. ${eng.ai ? 'Five AI agents then review the most security-relevant code.' : 'Add an Anthropic or Gemini API key in Settings to enable the five AI agents.'}</p>
        </div>
      </div>
    </div>
  </div>`;

  const $ = (s) => root.querySelector(s);
  const results = $('#results');

  // Tabs
  root.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => {
    tab = b.dataset.tab;
    root.querySelectorAll('[data-tab]').forEach((x) => { x.classList.toggle('active', x === b); x.setAttribute('aria-selected', String(x === b)); });
    root.querySelectorAll('[data-panel]').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== tab));
  }));

  // File picking
  const setPicked = (list) => {
    const skipped = { ignored: 0, binary: 0 };
    const keep = [];
    const seen = new Set();
    for (const it of list) {
      const p = it.path.replace(/\\/g, '/');
      if (IGNORED.test(p)) { skipped.ignored++; continue; }
      if (BINARY.test(p) && !/\.zip$/i.test(p)) { skipped.binary++; continue; }
      if (seen.has(p)) continue;
      seen.add(p);
      keep.push({ file: it.file, path: p });
    }
    picked = keep;
    const total = picked.reduce((n, x) => n + x.file.size, 0);
    const box = $('#picked');
    if (!picked.length) {
      box.innerHTML = list.length ? `<p class="hint">No scannable files in the selection (${skipped.binary} binary, ${skipped.ignored} in ignored folders).</p>` : '';
      return;
    }
    box.innerHTML = `
      <div class="file-summary">${picked.slice(0, 8).map((x) => `<div class="file-chip"><span>${esc(x.path)}</span><span class="sz">${fmtBytes(x.file.size)}</span></div>`).join('')}
        ${picked.length > 8 ? `<div class="hint">…and ${picked.length - 8} more files</div>` : ''}</div>
      <div class="hint" style="margin-top:6px">${picked.length} file${picked.length > 1 ? 's' : ''} · ${fmtBytes(total)}${skipped.binary + skipped.ignored ? ` · skipped ${skipped.binary + skipped.ignored}` : ''}
        ${total > MAX_TOTAL ? '<br><span style="color:var(--critical)">Too large — upload at most 100 MB. Try a .zip or a sub-folder.</span>' : ''}</div>
      <button class="btn btn-ghost btn-sm btn-block" id="clearPicked" style="margin-top:8px">${icon('x')}Clear selection</button>`;
    $('#clearPicked').onclick = () => { picked = []; $('#fiFiles').value = ''; $('#fiFolder').value = ''; setPicked([]); };
  };

  const dz = $('#dropZone');
  dz.onclick = () => $('#fiFiles').click();
  dz.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('#fiFiles').click(); } };
  $('#pickFiles').onclick = () => $('#fiFiles').click();
  $('#pickFolder').onclick = () => $('#fiFolder').click();
  // Reset the input after reading so picking the same file/folder again still fires "change".
  $('#fiFiles').onchange = (e) => { const fl = [...e.target.files]; e.target.value = ''; setPicked(fl.map((f) => ({ file: f, path: f.name }))); };
  $('#fiFolder').onchange = (e) => { const fl = [...e.target.files]; e.target.value = ''; setPicked(fl.map((f) => ({ file: f, path: f.webkitRelativePath || f.name }))); };
  let reading = false;
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', (e) => { if (!dz.contains(e.relatedTarget)) dz.classList.remove('over'); });
  dz.addEventListener('drop', async (e) => {
    e.preventDefault();
    dz.classList.remove('over');
    if (reading) return;
    const items = e.dataTransfer.items;
    if (items?.length && typeof items[0].webkitGetAsEntry === 'function') {
      reading = true;
      const h4 = dz.querySelector('h4');
      h4.textContent = 'Reading folder…';
      try {
        const got = await readEntries(items); // entries are taken synchronously before the first await
        if (!disposed) setPicked(got);
      } catch (ex) { if (!disposed) toast(`Could not read the dropped items: ${ex?.message || ex}`, 'err'); }
      reading = false;
      h4.textContent = 'Drop files, folders or a .zip';
    } else {
      setPicked([...e.dataTransfer.files].map((f) => ({ file: f, path: f.name })));
    }
  });

  // Analyze
  const btn = $('#analyzeBtn');
  const busy = (on) => { btn.disabled = on; btn.innerHTML = on ? '<div class="spinner"></div>Scanning…' : `${icon('scan')}Analyze`; };

  btn.onclick = async () => {
    if (btn.disabled) return; // no double submits
    let created;
    try {
      busy(true);
      if (tab === 'upload') {
        if (!picked.length) throw new Error('Choose files, a folder or a .zip first.');
        if (picked.reduce((n, x) => n + x.file.size, 0) > MAX_TOTAL) throw new Error('Selection is larger than 100 MB.');
        const fd = new FormData();
        fd.append('kind', 'files');
        fd.append('paths', JSON.stringify(picked.map((x) => x.path)));
        for (const x of picked) fd.append('files', x.file, x.file.name);
        const bar = $('#upProg');
        bar.firstElementChild.style.width = '0';
        bar.classList.remove('hidden');
        created = await upload('/scans', fd, (p) => { bar.firstElementChild.style.width = `${Math.round(p * 100)}%`; });
        bar.classList.add('hidden');
      } else if (tab === 'github') {
        const url = $('#ghUrl').value.trim();
        if (!/github\.com[/:][\w.-]+\/[\w.-]+/i.test(url) && !/^[\w.-]+\/[\w.-]+$/.test(url)) throw new Error('Enter a GitHub repository URL like https://github.com/owner/repo');
        created = await post('/scans', { kind: 'github', url });
      } else {
        const code = $('#codeIn').value;
        if (code.trim().length < 8) throw new Error('Paste some code first.');
        const lang = LANGS.find((l) => l[0] === $('#lang').value);
        created = await post('/scans', { kind: 'paste', code, filename: lang[0] === 'auto' ? guessFilename(code) : lang[2] });
      }
    } catch (e) {
      if (disposed) return;
      busy(false);
      $('#upProg').classList.add('hidden');
      return toast(e.message, 'err');
    }
    if (disposed) return;
    watch(created.id);
  };

  function watch(id) {
    results.innerHTML = '';
    const live = document.createElement('div');
    results.appendChild(live);
    stopLive = liveProgress(live, id, async (done) => {
      stopLive = null;
      busy(false);
      if (done.status !== 'completed') {
        results.innerHTML = `${agentsRow(null)}<div class="card empty-state">${icon('alert')}<h3>Scan ${esc(done.status)}</h3><p>${esc(done.error || '')}</p></div>`;
        return;
      }
      let scan;
      try { scan = await get(`/scans/${encodeURIComponent(id)}`); } catch (e) { if (!disposed) toast(e.message, 'err'); return; }
      if (disposed) return; // navigated away: don't pop the alert modal on another page
      results.innerHTML = `<div class="btn-row" style="justify-content:space-between;align-items:center;margin-bottom:10px">
        <b style="font-size:13px">${esc(scan.label)}</b><a class="btn btn-ghost btn-sm" href="#/scan/${encodeURIComponent(id)}">Open report page →</a></div><div id="rep"></div>`;
      renderReport(results.querySelector('#rep'), scan);
      maybeAlert(scan, state.settings?.alertThreshold || 'critical');
    });
  }

  return () => { disposed = true; stopLive?.(); };
}
