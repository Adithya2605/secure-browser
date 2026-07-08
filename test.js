const { app, BrowserWindow } = require('electron');
const path = require('path');

app.whenReady().then(() => {
  console.log('App ready');
  const NetworkGuard = require('./network-guard');
  const guard = new NetworkGuard({
    allowedDomains: ['localhost'],
    allowedCDNs: [],
    injectCSP: true
  });
  const { session } = require('electron');
  guard.attach(session.defaultSession);
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => callback(false));
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => callback({ cancel: false }));

  try {
    const win = new BrowserWindow({
      title: 'Test',
      fullscreen: true,
      kiosk: false,
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      closable: false,
      frame: false,
      show: false,
      alwaysOnTop: true,
      backgroundColor: '#1a1a2e',
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        devTools: false,
        webviewTag: false,
        allowRunningInsecureContent: false,
        navigateOnDragDrop: false,
      }
    });
    console.log('Window created successfully!');
    // win.close();
  } catch (err) {
    console.error('Error creating window:', err);
  }
  // app.quit();
});
