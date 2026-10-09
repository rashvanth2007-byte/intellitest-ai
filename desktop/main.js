/**
 * IntelliTest AI desktop app: runs the same Node server in-process on 127.0.0.1 and shows
 * the web UI in a BrowserWindow. Data lives in %APPDATA%\IntelliTest AI\data (SQLite).
 */
import { app, BrowserWindow, shell, dialog, Menu, ipcMain } from 'electron';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const PREFERRED_PORT = 47821; // fixed when possible so GitHub OAuth callback URLs stay stable

// app.quit() is asynchronous: without the guard below a second instance would still run boot()
// and start another server before quitting.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.exit(0);

let win = null;
let baseUrl = '';

function freePort(preferred) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => {
      const s2 = net.createServer();
      s2.listen(0, '127.0.0.1', () => { const p = s2.address().port; s2.close(() => resolve(p)); });
    });
    s.listen(preferred, '127.0.0.1', () => s.close(() => resolve(preferred)));
  });
}

function ensureEnvTemplate(file) {
  if (fs.existsSync(file)) return;
  fs.writeFileSync(file, [
    '# IntelliTest AI desktop configuration (optional). Restart the app after editing.',
    '# API keys can also be added per user from Settings inside the app.',
    '#ANTHROPIC_API_KEY=',
    '#GEMINI_API_KEY=',
    '#GITHUB_TOKEN=',
    '#CLAUDE_MODEL=',
    '#GEMINI_MODEL=',
    '# GitHub sign-in: create an OAuth app with callback http://127.0.0.1:47821/api/auth/github/callback',
    '# (if port 47821 is taken by another program the app falls back to a random port and GitHub sign-in fails).',
    '#GITHUB_CLIENT_ID=',
    '#GITHUB_CLIENT_SECRET=',
    '# Set to false to skip the OSV.dev dependency CVE lookup (fully offline).',
    '#OSV_ENABLED=true',
    '#CONCURRENT_SCANS=2',
    '',
  ].join('\r\n'));
}

async function boot() {
  const userData = app.getPath('userData');
  const envFile = path.join(userData, 'intellitest.env');
  fs.mkdirSync(userData, { recursive: true });
  ensureEnvTemplate(envFile);

  const port = await freePort(PREFERRED_PORT);
  baseUrl = `http://127.0.0.1:${port}`;
  Object.assign(process.env, {
    NODE_ENV: 'production',
    DATA_DIR: path.join(userData, 'data'),
    WEB_DIST: path.join(here, 'app', 'web'),
    INTELLITEST_ENV_FILE: envFile,
    APP_URL: baseUrl,
    PORT: String(port),
    HOST: '127.0.0.1',
    ALLOWED_HOSTS: `127.0.0.1:${port},localhost:${port}`,
  });

  const { startServer } = await import('./app/server.mjs');
  await startServer({ port, host: '127.0.0.1' });
  createWindow();

  // Auto-update (installed app only): check quietly a few seconds after start.
  try {
    const updater = await import('./app/updater.mjs');
    updater.initUpdater(() => win);
    checkUpdates = (manual) => updater.checkForUpdates(manual);
    setTimeout(() => checkUpdates(false), 8000);
  } catch (e) { console.error('[updater] unavailable', e.message); }
}

let checkUpdates = async (manual) => {
  if (manual) dialog.showMessageBox({ type: 'info', message: 'Updates are not available in this build.' });
  return { ok: false };
};
ipcMain.handle('app:version', () => app.getVersion());
ipcMain.handle('update:check', () => checkUpdates(true));

function createWindow() {
  win = new BrowserWindow({
    width: 1360,
    height: 880,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0A0E17',
    title: 'IntelliTest AI',
    icon: path.join(here, 'build', 'icon.png'),
    autoHideMenuBar: true,
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false, preload: path.join(here, 'preload.cjs') },
  });
  win.once('ready-to-show', () => win.show());

  // If the page fails to load, still show the window (Chromium's error page + View → Reload) instead of nothing.
  win.webContents.once('did-fail-load', () => { if (!win.isDestroyed() && !win.isVisible()) win.show(); });
  win.on('closed', () => { win = null; });
  win.loadURL(baseUrl);
}

const isAppUrl = (u) => !!baseUrl && (u === baseUrl || u.startsWith(`${baseUrl}/`));
// GitHub sign-in / 2FA / OAuth consent pages may load in-window so the OAuth redirect comes back to the app.
const isGithubAuth = (u) => /^https:\/\/github\.com\/(login|session|sessions|signup|join|password_reset)([/?#]|$)/.test(u);
const openOutside = (url) => { if (/^https?:\/\//i.test(url)) shell.openExternal(url).catch(() => {}); };

/**
 * Navigation rules for every window (main window and report pop-ups): only our UI and the GitHub
 * sign-in pages load inside the app; other http(s) links open in the default browser; anything
 * else (file://, javascript:, custom protocols) is blocked. Report downloads use <a download>,
 * which never navigates, so Electron's normal save dialog handles them.
 */
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (e, url) => {
    if (isAppUrl(url) || isGithubAuth(url)) return;
    e.preventDefault();
    openOutside(url);
  });
  contents.on('will-attach-webview', (e) => e.preventDefault());
  contents.setWindowOpenHandler(({ url }) => {
    if (isAppUrl(url)) {
      return {
        action: 'allow',
        overrideBrowserWindowOptions: {
          autoHideMenuBar: true, backgroundColor: '#0A0E17',
          webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false },
        },
      };
    }
    openOutside(url);
    return { action: 'deny' };
  });
});

app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.show(); win.focus(); } });
app.on('window-all-closed', () => app.quit());

if (gotLock) app.whenReady().then(() => {
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'File', submenu: [
      { label: 'Open data folder', click: () => shell.openPath(app.getPath('userData')) },
      { label: 'Edit configuration (API keys, GitHub OAuth)…', click: () => shell.openPath(path.join(app.getPath('userData'), 'intellitest.env')) },
      { type: 'separator' }, { role: 'quit' },
    ] },
    { label: 'View', submenu: [{ role: 'reload' }, { role: 'toggleDevTools' }, { type: 'separator' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }, { role: 'togglefullscreen' }] },
    { label: 'Help', submenu: [
      { label: 'Check for updates…', click: () => checkUpdates(true) },
      { type: 'separator' },
      { label: `IntelliTest AI ${app.getVersion()}`, enabled: false },
    ] },
  ]));
  boot().catch((e) => {
    dialog.showErrorBox('IntelliTest AI failed to start', String(e?.stack || e));
    app.quit();
  });
});
