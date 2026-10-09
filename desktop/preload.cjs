// Minimal bridge for the web UI (sandboxed renderer: CommonJS + contextBridge only).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('intellitestDesktop', {
  getVersion: () => ipcRenderer.invoke('app:version'),
  checkForUpdates: () => ipcRenderer.invoke('update:check'),
  getUpdateStatus: () => ipcRenderer.invoke('update:status'),
  downloadUpdate: () => ipcRenderer.invoke('update:download'),
  installUpdate: () => ipcRenderer.invoke('update:install'),
  /** Subscribe to live update status; returns an unsubscribe function. */
  onUpdateStatus: (cb) => {
    const fn = (_e, s) => cb(s);
    ipcRenderer.on('update:status', fn);
    return () => ipcRenderer.removeListener('update:status', fn);
  },
});
