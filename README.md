# Secure Assessment Browser

A minimal Electron.js application that locks candidates into a single assessment URL, preventing DevTools, new tabs, navigation hijacking, and other exam-integrity threats.

---

## 📁 Project Structure

```
secure-browser/
├── main.js          # Main Electron process (window + security policies)
├── preload.js       # Renderer-side protections (keyboard, context menu)
├── config.json      # ← Edit this to configure your URL
├── package.json     # Dependencies & build config
├── assets/
│   └── icon.ico     # (Optional) Windows installer icon
└── README.md
```

---

## ⚙️ Step 1 — Configure Your Assessment URL

Open **`config.json`** and set your values:

```json
{
  "allowedUrl": "https://your-assessment-platform.com",
  "windowTitle": "Secure Assessment Browser",
  "fullscreen": true,
  "kiosk": false,
  "allowedDomains": [
    "your-assessment-platform.com"
  ]
}
```

| Key | Description |
|-----|-------------|
| `allowedUrl` | The exact URL loaded on launch |
| `allowedDomains` | Whitelist — subdomains are auto-allowed |
| `fullscreen` | `true` = fullscreen (ESC re-enters automatically) |
| `kiosk` | `true` = OS-level kiosk (hides taskbar on Windows) |

---

## 🛠️ Step 2 — Install

```bash
cd secure-browser
npm install
```

---

## ▶️ Step 3 — Run (Development)

```bash
npm start
```

---

## 📦 Step 4 — Build Windows Installer

```bash
npm run build
```

Output: `dist/Secure Assessment Browser Setup.exe`

> **Note:** For the icon, place a 256×256 `.ico` file at `assets/icon.ico` before building.

---

## 🔒 Security Features

| Feature | Implementation |
|---------|----------------|
| Fullscreen lockdown | `fullscreen: true` + `leave-full-screen` re-enters |
| Navigation whitelist | `will-navigate`, `will-redirect`, `did-navigate` events |
| Request filtering | `session.webRequest.onBeforeRequest` blocks all non-whitelisted URLs |
| New window / tab blocked | `setWindowOpenHandler → deny` |
| DevTools disabled | `devTools: false` in webPreferences + `devtools-opened` event |
| Context menu disabled | `contextmenu` event cancelled in preload |
| Keyboard shortcuts blocked | `keydown` filter in preload (F12, Ctrl+Shift+I, Ctrl+R, etc.) |
| Node integration off | `nodeIntegration: false` |
| Context isolation on | `contextIsolation: true` |
| Sandbox on | `sandbox: true` |
| No `<webview>` | `webviewTag: false` |
| Frame / blob / data URLs | Blocked by `isAllowed()` protocol check |
| Drag-and-drop | Blocked in preload |

---

## 🚪 Graceful Exit (After Assessment Submission)

If your assessment page needs to close the browser after the candidate submits, call:

```javascript
// From inside the assessment page (injected by your platform)
window.secureBrowser.assessmentComplete();
```

This triggers a clean `app.quit()` in the main process.

---

## ⚠️ Limitations & Notes

- **Windows key / Task Manager (Ctrl+Shift+Esc)**: OS-level shortcuts cannot be fully blocked from within a user-mode Electron app. For maximum lockdown, combine with Windows Group Policy or a dedicated kiosk OS image.
- **Alt+Tab**: Similarly OS-level; consider enabling `kiosk: true` which hides the taskbar.
- **HTTP vs HTTPS**: The `allowedDomains` whitelist works for both, but ensure your platform uses HTTPS in production.
- **Multiple subdomains**: Add each as a separate entry, e.g. `["auth.company.com", "assessment.company.com"]`.
