/**
 * launch-preload.js — Preload script for the wizard phase
 *
 * Exposes a narrow, named IPC bridge (window.sebWizard) to the launch wizard
 * renderer. Uses contextBridge so the renderer cannot reach ipcRenderer directly.
 *
 * Active ONLY during the wizard phase (steps 1-8).
 * After wizard:launch-exam fires, main.js reloads the window with the exam
 * preload (preload.js) and the exam URL.
 */
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sebWizard', {
  /** Step 1 & 2 — Allow OS media permission dialog to appear */
  enableMediaPermissions:  () => ipcRenderer.invoke('wizard:enable-media'),

  /** Step 3 — Acknowledge screen recording policy */
  confirmScreenPolicy:     () => ipcRenderer.invoke('wizard:confirm-screen'),

  /** Step 4 — Tell main process to enter fullscreen */
  enterFullscreen:         () => ipcRenderer.invoke('wizard:enter-fullscreen'),

  /**
   * Step 5 — Persist candidate identity.
   * @param {{ name: string, examId: string, photoDataUrl: string }} data
   */
  submitIdentity:          (data) => ipcRenderer.invoke('wizard:submit-identity', data),

  /**
   * Step 6 — Run pre-launch security checks.
   * Resolves to { checks: CheckResult[], allPassed: boolean }
   * CheckResult: { id, label, passed: boolean|'warn', message }
   */
  runSecurityCheck:        () => ipcRenderer.invoke('wizard:run-security-check'),

  /**
   * Step 7 — Activate all security controls (FocusGuard, RiskEngine, monitors).
   * Resolves to { ok: boolean }.
   */
  enterLockdown:           () => ipcRenderer.invoke('wizard:enter-lockdown'),

  /**
   * Step 8 — Switch preload to exam preload.js and navigate to the exam URL.
   * The wizard page will be unloaded immediately after this resolves.
   */
  launchExam:              () => ipcRenderer.invoke('wizard:launch-exam'),

  /**
   * Opens the Windows Privacy Settings page for camera or microphone.
   * @param {'camera'|'microphone'} type
   */
  openPrivacySettings:     (type) => ipcRenderer.invoke('wizard:open-privacy-settings', type),

  /**
   * Step 6 — Close a suspicious application by process name.
   * @param {string} processName  e.g. 'msedge.exe'
   * Resolves to { ok: boolean, error?: string }
   */
  killProcess:             (processName) => ipcRenderer.invoke('wizard:kill-process', processName),
});
