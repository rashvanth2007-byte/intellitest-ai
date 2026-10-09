/**
 * Auto-update via electron-updater + GitHub Releases.
 * Bundled by scripts/bundle.mjs into app/updater.mjs (the packaged app has no node_modules).
 *
 * The current status is pushed to the UI (Settings → About & updates shows it next to the button):
 *   idle → checking → available → downloading (percent, MB, speed) → downloaded → (restart)
 *   or   → up-to-date / error
 * Start-up checks and Help → Check for updates use native dialogs; the Settings button is
 * "inline": no dialogs, the UI shows the status and the Download / Restart buttons instead.
 */
import { app, dialog, BrowserWindow } from 'electron';
import updaterPkg from 'electron-updater';

const { autoUpdater } = updaterPkg;

let getWindow = () => null;
let manual = false;   // show "up to date" / error dialogs
let inline = false;   // the Settings page drives the flow: no dialogs at all

let status = { phase: 'idle', current: app.getVersion() };

function setStatus(patch) {
  status = { ...status, ...patch, current: app.getVersion(), at: Date.now() };
  for (const w of BrowserWindow.getAllWindows()) {
    if (!w.isDestroyed()) w.webContents.send('update:status', status);
  }
}
export const getStatus = () => status;

const box = (opts) => dialog.showMessageBox(getWindow() || undefined, { title: 'IntelliTest AI updates', noLink: true, ...opts });
const busy = () => ['checking', 'downloading'].includes(status.phase);

export function initUpdater(windowGetter) {
  getWindow = windowGetter;
  autoUpdater.autoDownload = false;          // always ask first
  autoUpdater.autoInstallOnAppQuit = true;   // a downloaded update installs on next quit anyway

  autoUpdater.on('checking-for-update', () => setStatus({ phase: 'checking', message: null }));

  autoUpdater.on('update-available', async (info) => {
    setStatus({ phase: 'available', version: info.version, notes: stripHtml(info.releaseNotes).slice(0, 800), percent: 0 });
    if (inline) return; // the Settings page shows a Download button
    const { response } = await box({
      type: 'info',
      message: `IntelliTest AI ${info.version} is available`,
      detail: `You have ${app.getVersion()}. Download and install the update now?\n\n${status.notes || ''}`,
      buttons: ['Download', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) downloadUpdate();
  });

  autoUpdater.on('update-not-available', () => {
    setStatus({ phase: 'up-to-date', version: null });
    if (manual && !inline) box({ type: 'info', message: 'You are up to date', detail: `IntelliTest AI ${app.getVersion()} is the latest version.` });
  });

  autoUpdater.on('download-progress', (p) => {
    getWindow()?.setProgressBar(Math.max(0.01, p.percent / 100));
    setStatus({ phase: 'downloading', percent: p.percent, transferred: p.transferred, total: p.total, bytesPerSecond: p.bytesPerSecond });
  });

  autoUpdater.on('update-downloaded', async (info) => {
    getWindow()?.setProgressBar(-1);
    setStatus({ phase: 'downloaded', version: info.version, percent: 100 });
    if (inline) return; // the Settings page shows "Restart & install"
    const { response } = await box({
      type: 'info',
      message: `Update ${info.version} is ready`,
      detail: 'Restart IntelliTest AI now to finish installing? Your scans and settings are kept.',
      buttons: ['Restart now', 'On next launch'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) installUpdate();
  });

  autoUpdater.on('error', (e) => fail(e));
}

function fail(e) {
  getWindow()?.setProgressBar(-1);
  console.error('[updater]', e?.message || e);
  setStatus({ phase: 'error', message: friendly(e) });
  if (manual && !inline) box({ type: 'warning', message: 'Could not update', detail: friendly(e) });
}

function friendly(e) {
  const m = String(e?.message || e);
  if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT|ECONNRESET|net::/i.test(m)) return 'No internet connection. Try again later.';
  if (/404|latest\.yml|No published versions/i.test(m)) return 'No published release was found yet.';
  if (/app-update\.yml/i.test(m)) return 'This build was made without update information. Install the latest version from the download page once.';
  if (/sha512|checksum/i.test(m)) return 'The download was corrupted. Please try again.';
  return m.slice(0, 300);
}

const stripHtml = (n) => (Array.isArray(n) ? n.map((x) => x.note).join('\n') : String(n || '')).replace(/<[^>]+>/g, '').trim();

/**
 * isManual: user asked (show "up to date" / errors). isInline: asked from the Settings page,
 * which shows the status itself, so no dialogs.
 */
export async function checkForUpdates(isManual = false, isInline = false) {
  manual = isManual;
  inline = isInline;
  if (!app.isPackaged) {
    setStatus({ phase: 'error', message: 'Updates are only available in the installed app (this is a development build).' });
    if (isManual && !isInline) box({ type: 'info', message: 'Updates are only available in the installed app', detail: 'You are running a development build.' });
    return status;
  }
  if (busy() || status.phase === 'downloaded') return status;
  setStatus({ phase: 'checking', message: null });
  try {
    await autoUpdater.checkForUpdates();
  } catch (e) {
    fail(e);
  }
  return status;
}

export function downloadUpdate() {
  if (status.phase !== 'available' && status.phase !== 'error') return status;
  setStatus({ phase: 'downloading', percent: 0, transferred: 0, total: 0, bytesPerSecond: 0 });
  autoUpdater.downloadUpdate().catch((e) => fail(e));
  return status;
}

export function installUpdate() {
  if (status.phase !== 'downloaded') return status;
  setStatus({ phase: 'installing' });
  // Close silently and run the installer, then reopen the app.
  setImmediate(() => autoUpdater.quitAndInstall(true, true));
  return status;
}
