/**
 * Auto-update via electron-updater + GitHub Releases.
 * Bundled by scripts/bundle.mjs into app/updater.mjs (the packaged app has no node_modules).
 *
 * Flow: check on start-up and from Help → Check for updates → ask before downloading →
 * show progress on the taskbar → ask to restart and install.
 */
import { app, dialog } from 'electron';
import updaterPkg from 'electron-updater';

const { autoUpdater } = updaterPkg;

let getWindow = () => null;
let busy = false;
let manual = false;

const box = (opts) => dialog.showMessageBox(getWindow() || undefined, { title: 'IntelliTest AI updates', noLink: true, ...opts });

export function initUpdater(windowGetter) {
  getWindow = windowGetter;
  autoUpdater.autoDownload = false;          // always ask first
  autoUpdater.autoInstallOnAppQuit = true;   // a downloaded update installs on next quit anyway

  autoUpdater.on('update-available', async (info) => {
    const { response } = await box({
      type: 'info',
      message: `IntelliTest AI ${info.version} is available`,
      detail: `You have ${app.getVersion()}. Download and install the update now?\n\n${stripHtml(info.releaseNotes).slice(0, 800)}`,
      buttons: ['Download', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) {
      autoUpdater.downloadUpdate().catch((e) => fail(e));
    } else {
      busy = false;
    }
  });

  autoUpdater.on('update-not-available', () => {
    busy = false;
    if (manual) box({ type: 'info', message: 'You are up to date', detail: `IntelliTest AI ${app.getVersion()} is the latest version.` });
  });

  autoUpdater.on('download-progress', (p) => getWindow()?.setProgressBar(Math.max(0.01, p.percent / 100)));

  autoUpdater.on('update-downloaded', async (info) => {
    getWindow()?.setProgressBar(-1);
    busy = false;
    const { response } = await box({
      type: 'info',
      message: `Update ${info.version} is ready`,
      detail: 'Restart IntelliTest AI now to finish installing? Your scans and settings are kept.',
      buttons: ['Restart now', 'On next launch'],
      defaultId: 0,
      cancelId: 1,
    });
    if (response === 0) setImmediate(() => autoUpdater.quitAndInstall(false, true));
  });

  autoUpdater.on('error', (e) => fail(e));
}

function fail(e) {
  busy = false;
  getWindow()?.setProgressBar(-1);
  console.error('[updater]', e?.message || e);
  if (manual) box({ type: 'warning', message: 'Could not check for updates', detail: friendly(e) });
}

function friendly(e) {
  const m = String(e?.message || e);
  if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT|net::/i.test(m)) return 'No internet connection. Try again later.';
  if (/404|latest\.yml|No published versions/i.test(m)) return 'No published release was found yet. (Publish one with "npm run release:win".)';
  if (/app-update\.yml/i.test(m)) return 'This build was made without update information. Rebuild it with GH_OWNER and GH_REPO set.';
  return m.slice(0, 300);
}

const stripHtml = (n) => (Array.isArray(n) ? n.map((x) => x.note).join('\n') : String(n || '')).replace(/<[^>]+>/g, '').trim();

/** isManual: show "up to date" / error dialogs (Help menu, Settings button). */
export async function checkForUpdates(isManual = false) {
  manual = isManual;
  if (!app.isPackaged) {
    if (isManual) box({ type: 'info', message: 'Updates are only available in the installed app', detail: 'You are running a development build.' });
    return { ok: false, reason: 'dev' };
  }
  if (busy) return { ok: true, reason: 'busy' };
  busy = true;
  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (e) {
    fail(e);
    return { ok: false, reason: friendly(e) };
  }
}
