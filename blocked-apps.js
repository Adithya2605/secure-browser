/**
 * blocked-apps.js — Suspicious process blocklist
 *
 * Each entry describes one executable that should NOT be running during
 * a secure assessment. The monitor flags (but does NOT kill) these processes.
 *
 * Fields:
 *   name        {string}   Lowercase .exe name as reported by the OS
 *   category    {string}   Logical group for reporting / filtering
 *   description {string}   Human-readable reason for flagging
 *   severity    {string}   'HIGH' | 'MEDIUM' | 'LOW'
 *
 * To customise: add/remove entries, or load this list from config.json
 * if you need per-deployment customisation without touching code.
 */

'use strict';

/** @type {Array<{name:string, category:string, description:string, severity:string}>} */
const BLOCKED_APPS = [

  // ── Screen sharing & video conferencing ─────────────────────────────────────
  { name: 'zoom.exe',           category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Zoom — live screen sharing' },
  { name: 'zoomit.exe',         category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'ZoomIt — presentation / annotation tool' },
  { name: 'teams.exe',          category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Microsoft Teams — screen share & chat' },
  { name: 'ms-teams.exe',       category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Microsoft Teams (new client)' },
  { name: 'webexmta.exe',       category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Cisco WebEx' },
  { name: 'webex.exe',          category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Cisco WebEx' },
  { name: 'gotomeeting.exe',    category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'GoToMeeting' },
  { name: 'skype.exe',          category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Skype — video & screen share' },
  { name: 'skypehost.exe',      category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Skype UWP host process' },
  { name: 'lync.exe',           category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Skype for Business (Lync)' },
  { name: 'slack.exe',          category: 'SCREEN_SHARE', severity: 'MEDIUM', description: 'Slack — includes Huddles screen share' },
  { name: 'discord.exe',        category: 'SCREEN_SHARE', severity: 'MEDIUM', description: 'Discord — Go Live screen share' },
  { name: 'meet.exe',           category: 'SCREEN_SHARE', severity: 'HIGH',   description: 'Google Meet desktop app' },

  // ── Screen recording ─────────────────────────────────────────────────────────
  { name: 'obs64.exe',          category: 'RECORDING',    severity: 'HIGH',   description: 'OBS Studio (64-bit) — screen recorder / stream' },
  { name: 'obs32.exe',          category: 'RECORDING',    severity: 'HIGH',   description: 'OBS Studio (32-bit)' },
  { name: 'obs.exe',            category: 'RECORDING',    severity: 'HIGH',   description: 'OBS Studio (legacy)' },
  { name: 'bdcam.exe',          category: 'RECORDING',    severity: 'HIGH',   description: 'Bandicam screen recorder' },
  { name: 'fraps.exe',          category: 'RECORDING',    severity: 'HIGH',   description: 'Fraps screen recorder' },
  { name: 'action.exe',         category: 'RECORDING',    severity: 'HIGH',   description: 'Action! screen recorder' },
  { name: 'camtasia.exe',       category: 'RECORDING',    severity: 'HIGH',   description: 'Camtasia screen recorder' },
  { name: 'screencastify.exe',  category: 'RECORDING',    severity: 'HIGH',   description: 'Screencastify recorder' },
  { name: 'flashback.exe',      category: 'RECORDING',    severity: 'HIGH',   description: 'FlashBack screen recorder' },
  { name: 'xsplit.core.exe',    category: 'RECORDING',    severity: 'HIGH',   description: 'XSplit Broadcaster' },
  { name: 'sharex.exe',         category: 'RECORDING',    severity: 'MEDIUM', description: 'ShareX — screenshot & recording tool' },

  // ── Remote access / remote desktop ───────────────────────────────────────────
  { name: 'teamviewer.exe',        category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'TeamViewer — full remote control' },
  { name: 'teamviewer_service.exe',category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'TeamViewer background service' },
  { name: 'anydesk.exe',           category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'AnyDesk remote desktop' },
  { name: 'ammyy.exe',             category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'Ammyy Admin remote access' },
  { name: 'logmein.exe',           category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'LogMeIn remote access' },
  { name: 'mstsc.exe',             category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'Windows Remote Desktop (mstsc)' },
  { name: 'vncviewer.exe',         category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'VNC Viewer — remote desktop' },
  { name: 'vncserver.exe',         category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'VNC Server' },
  { name: 'tvnserver.exe',         category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'TightVNC server' },
  { name: 'ultraviewer.exe',       category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'UltraViewer remote access' },
  { name: 'rustdesk.exe',          category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'RustDesk open-source remote desktop' },
  { name: 'parsec.exe',            category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'Parsec remote desktop' },
  { name: 'chrome remote desktop host.exe', category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'Chrome Remote Desktop host' },
  { name: 'remoting_host.exe',     category: 'REMOTE_ACCESS', severity: 'HIGH', description: 'Chrome Remote Desktop host process' },

  // ── Other web browsers ───────────────────────────────────────────────────────
  { name: 'chrome.exe',          category: 'BROWSER',     severity: 'MEDIUM', description: 'Google Chrome' },
  { name: 'firefox.exe',         category: 'BROWSER',     severity: 'MEDIUM', description: 'Mozilla Firefox' },
  { name: 'msedge.exe',          category: 'BROWSER',     severity: 'MEDIUM', description: 'Microsoft Edge' },
  { name: 'brave.exe',           category: 'BROWSER',     severity: 'MEDIUM', description: 'Brave Browser' },
  { name: 'opera.exe',           category: 'BROWSER',     severity: 'MEDIUM', description: 'Opera Browser' },
  { name: 'vivaldi.exe',         category: 'BROWSER',     severity: 'MEDIUM', description: 'Vivaldi Browser' },
  { name: 'tor browser.exe',     category: 'BROWSER',     severity: 'HIGH',   description: 'Tor Browser — anonymous browsing' },
  { name: 'firefox esr.exe',     category: 'BROWSER',     severity: 'MEDIUM', description: 'Firefox ESR' },
  { name: 'iexplore.exe',        category: 'BROWSER',     severity: 'LOW',    description: 'Internet Explorer (legacy)' },
  { name: 'safari.exe',          category: 'BROWSER',     severity: 'MEDIUM', description: 'Safari (Windows port)' },

  // ── AI / LLM desktop tools ───────────────────────────────────────────────────
  { name: 'claude.exe',          category: 'AI_TOOL',     severity: 'HIGH',   description: 'Anthropic Claude desktop app' },
  { name: 'chatgpt.exe',         category: 'AI_TOOL',     severity: 'HIGH',   description: 'OpenAI ChatGPT desktop app' },
  { name: 'copilot.exe',         category: 'AI_TOOL',     severity: 'HIGH',   description: 'Microsoft Copilot desktop app' },
  { name: 'gemini.exe',          category: 'AI_TOOL',     severity: 'HIGH',   description: 'Google Gemini desktop app' },
  { name: 'perplexity.exe',      category: 'AI_TOOL',     severity: 'HIGH',   description: 'Perplexity AI desktop app' },

  // ── Virtual machines ─────────────────────────────────────────────────────────
  { name: 'vmware.exe',          category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'VMware Workstation' },
  { name: 'vmplayer.exe',        category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'VMware Player' },
  { name: 'virtualbox.exe',      category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'Oracle VirtualBox' },
  { name: 'vboxheadless.exe',    category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'VirtualBox headless VM (hidden)' },
  { name: 'hyperv.exe',          category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'Hyper-V Manager' },
  { name: 'vmconnect.exe',       category: 'VIRTUAL_MACHINE', severity: 'HIGH', description: 'Hyper-V VM Connect' },
];

module.exports = BLOCKED_APPS;
