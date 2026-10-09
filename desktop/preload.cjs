// Minimal, read-only bridge for the web UI (sandboxed renderer: CommonJS + contextBridge only).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('intellitestDesktop', {
  getVersion: () => ipcRenderer.invoke('app:version'),
  checkForUpdates: () => ipcRenderer.invoke('update:check'),
});
