"""Artzain Chat (local) — the server behind the ``artzain gui`` command.

One surface, one name: this is the **local chat client**, not the hosted
dashboard (that lives at ``<base>/dashboard.html``; requests to
``/dashboard*`` on the local port redirect there).

Starts a lightweight HTTP proxy on localhost and opens the default browser.
All ``/api/*`` traffic is forwarded to the configured CogNEXUS platform API,
including SSE-streamed conversation responses.

If a ``COGNEXUS_API_KEY`` is present the user goes directly into the chat —
no login form required.  The proxy exchanges the key for a short-lived JWT via
``POST /api/auth/token`` and serves it to the browser via ``GET /gui/bootstrap``.

Prompt-defence screening is run locally (via the SDK) before every outbound
message.  Results appear as inline warnings in the chat thread.

Usage::

    artzain gui                     # random free port, opens browser
    artzain gui --port 8765         # specific port
    artzain gui --no-browser        # headless (CI / remote machines)
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
)

_DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# ──────────────────────────────────────────────────────────────────────────────
# Embedded chat UI  (self-contained, no build step required)
# ──────────────────────────────────────────────────────────────────────────────
# Template placeholders replaced at serve-time:
#   __COGNEXUS_ORIGIN__  →  upstream base URL shown in login fallback

_GUI_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <meta name="theme-color" content="#07080a" />
  <title>Artzain Chat (local)</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,wght@0,300;0,400;0,500;1,300&family=Plus+Jakarta+Sans:wght@700;800&display=swap" rel="stylesheet" />
  <script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js" crossorigin="anonymous"></script>
  <style>
    :root {
      --black: #07080a;
      --surface: #111318;
      --surface-2: #181b22;
      --border: rgba(255,255,255,0.07);
      --teal: #00d4aa;
      --teal-dim: rgba(0,212,170,0.12);
      --text: #e8eaf0;
      --muted: #7a7f8e;
      --muted-2: #4a4f5e;
      --white: #ffffff;
      --red: #f87171;
      --amber: #fbbf24;
      --amber-dim: rgba(251,191,36,0.1);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; overflow: hidden; }
    body {
      height: 100dvh;
      background: var(--black);
      color: var(--text);
      font-family: 'DM Sans', sans-serif;
      font-size: 16px;
      line-height: 1.45;
    }
    body::before {
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,212,170,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,170,0.025) 1px, transparent 1px);
      background-size: 60px 60px;
      pointer-events: none; z-index: 0;
    }

    /* ── BOOT SPLASH ── */
    #bootView {
      position: relative; z-index: 2;
      height: 100dvh;
      display: flex; align-items: center; justify-content: center;
    }
    .boot-brand {
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 800; font-size: 1.6rem; color: var(--white);
    }
    .boot-brand span { color: var(--teal); }
    .boot-sub { font-size: 0.8rem; color: var(--muted); margin-top: 0.5rem; text-align: center; }
    @keyframes pwa-spin { to { transform: rotate(360deg); } }
    .boot-spinner {
      width: 22px; height: 22px; margin: 1rem auto 0;
      border: 2.5px solid rgba(0,212,170,0.2); border-top-color: var(--teal);
      border-radius: 50%; animation: pwa-spin 0.8s linear infinite;
    }

    /* ── LOGIN FALLBACK ── */
    #loginView {
      position: relative; z-index: 1;
      height: 100dvh;
      display: flex; align-items: center; justify-content: center;
      padding: 1rem;
    }
    .login-card {
      width: 100%; max-width: 400px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 16px; padding: 2rem 2rem 1.75rem;
    }
    .login-brand {
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 800; font-size: 1.5rem; color: var(--white); margin-bottom: 0.2rem;
    }
    .login-brand span { color: var(--teal); }
    .login-subtitle { font-size: 0.82rem; color: var(--muted); margin-bottom: 1.75rem; }
    .login-field { margin-bottom: 0.75rem; }
    .login-field label {
      display: block; font-size: 0.72rem; font-weight: 600;
      color: var(--muted); margin-bottom: 0.3rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }
    .login-field input {
      width: 100%; padding: 0.65rem 0.8rem;
      background: var(--surface-2); border: 1px solid var(--border);
      border-radius: 8px; color: var(--text);
      font-family: inherit; font-size: 0.92rem; outline: none;
      transition: border-color 0.15s;
    }
    .login-field input:focus { border-color: rgba(0,212,170,0.45); }
    .login-btn {
      width: 100%; min-height: 44px; margin-top: 0.5rem;
      background: var(--teal); color: #07080a;
      border: none; border-radius: 8px;
      font-family: inherit; font-size: 0.92rem; font-weight: 700;
      cursor: pointer;
    }
    .login-btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .login-error { margin-top: 0.75rem; font-size: 0.8rem; color: var(--red); min-height: 1.2rem; }
    .login-origin { margin-top: 1.25rem; font-size: 0.72rem; color: var(--muted-2); text-align: center; }
    .login-origin strong { color: var(--muted); }

    /* ── CHAT ── */
    #chatView {
      position: relative; z-index: 1;
      height: 100dvh;
      display: flex; flex-direction: column;
    }
    .chat-header {
      flex-shrink: 0;
      display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;
      padding: 0.65rem 0.9rem;
      border-bottom: 1px solid var(--border);
      background: rgba(7,8,10,0.92); backdrop-filter: blur(12px);
    }
    .chat-brand {
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 800; font-size: 1.05rem; color: var(--white);
    }
    .chat-brand span { color: var(--teal); }
    .chat-header-actions { display: flex; align-items: center; gap: 0.4rem; }
    .chat-user-email { font-size: 0.75rem; color: var(--muted); }
    .chat-new-btn {
      display: inline-flex; align-items: center; gap: 0.35rem;
      min-height: 36px; padding: 0 0.65rem;
      border-radius: 8px; border: 1px solid rgba(0,212,170,0.35);
      background: var(--teal-dim); color: var(--teal);
      font-size: 0.8rem; font-weight: 600; font-family: inherit; cursor: pointer;
    }
    .chat-new-btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .chat-signout-btn {
      min-height: 36px; padding: 0 0.65rem;
      border-radius: 8px; border: 1px solid var(--border);
      background: var(--surface); color: var(--muted);
      font-size: 0.78rem; font-family: inherit; cursor: pointer;
    }

    /* Agent pills */
    .chat-agents-hint {
      flex-shrink: 0;
      padding: 0.28rem 0.75rem;
      border-bottom: 1px solid var(--border);
      background: rgba(7,8,10,0.7);
      display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap;
    }
    .chat-agents-hint-label { font-size: 0.67rem; color: var(--muted-2); white-space: nowrap; }
    .chat-agent-pill {
      font-size: 0.67rem; font-weight: 600;
      color: var(--teal); background: var(--teal-dim);
      border: 1px solid rgba(0,212,170,0.2);
      border-radius: 5px; padding: 0.1rem 0.45rem;
      cursor: pointer; font-family: inherit; white-space: nowrap;
    }
    .chat-agent-pill:hover { background: rgba(0,212,170,0.2); }
    .chat-agent-pill.active {
      background: rgba(0,212,170,0.25);
      border-color: rgba(0,212,170,0.5);
      color: var(--white);
    }

    /* Thread */
    .chat-thread-wrap {
      flex: 1; min-height: 0; overflow-y: auto;
      padding: 1.25rem 0.9rem;
      scroll-behavior: smooth;
    }
    .chat-thread-wrap::-webkit-scrollbar { width: 4px; }
    .chat-thread-wrap::-webkit-scrollbar-track { background: transparent; }
    .chat-thread-wrap::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    /* ── Empty state / quickstarts ── */
    .quickstart-wrap {
      display: flex; flex-direction: column; align-items: center;
      padding: 2rem 0.5rem 1rem;
      gap: 0.5rem;
    }
    .quickstart-brand {
      font-family: 'Plus Jakarta Sans', sans-serif;
      font-weight: 800; font-size: 1.35rem; color: var(--white);
      margin-bottom: 0.2rem;
    }
    .quickstart-brand span { color: var(--teal); }
    .quickstart-tagline { font-size: 0.82rem; color: var(--muted); margin-bottom: 1rem; }
    .quickstart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 0.5rem;
      width: 100%; max-width: 680px;
    }
    .quickstart-chip {
      display: flex; align-items: flex-start; gap: 0.5rem;
      padding: 0.65rem 0.75rem;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; cursor: pointer; text-align: left;
      font-family: inherit; color: var(--text); font-size: 0.82rem;
      line-height: 1.4; transition: border-color 0.15s, background 0.15s;
    }
    .quickstart-chip:hover { border-color: rgba(0,212,170,0.35); background: var(--surface-2); }
    .quickstart-chip-icon { font-size: 1rem; flex-shrink: 0; margin-top: 0.05rem; }
    .quickstart-chip-label { color: var(--muted); font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.15rem; }

    /* Messages */
    .chat-msg { margin-bottom: 1rem; }
    .chat-msg--user { display: flex; flex-direction: column; align-items: flex-end; }
    .chat-msg--assistant { display: flex; flex-direction: column; align-items: flex-start; }
    .chat-msg--system { text-align: center; }
    .chat-msg-sender {
      font-size: 0.7rem; font-weight: 600; color: var(--muted);
      margin-bottom: 0.25rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }
    .chat-msg--user .chat-msg-sender { color: var(--teal); }
    .chat-msg-bubble {
      max-width: min(600px, 92%);
      padding: 0.65rem 0.85rem; border-radius: 12px;
      font-size: 0.92rem; line-height: 1.55; word-break: break-word;
    }
    .chat-msg--user .chat-msg-bubble {
      background: var(--teal-dim); border: 1px solid rgba(0,212,170,0.2); color: var(--text);
    }
    .chat-msg--assistant .chat-msg-bubble {
      background: var(--surface); border: 1px solid var(--border); color: var(--text);
    }
    .chat-msg--system .chat-msg-bubble {
      display: inline-block;
      background: rgba(0,212,170,0.07); border: 1px solid rgba(0,212,170,0.15);
      color: var(--muted); font-size: 0.78rem;
      border-radius: 8px; padding: 0.3rem 0.75rem;
    }
    .chat-msg-time { font-size: 0.65rem; color: var(--muted-2); margin-top: 0.3rem; }

    /* ── Defense banner ── */
    .defense-banner {
      display: flex; align-items: flex-start; gap: 0.6rem;
      margin-bottom: 0.65rem;
      padding: 0.55rem 0.75rem;
      border-radius: 10px; font-size: 0.82rem; line-height: 1.45;
    }
    .defense-banner--blocked {
      background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.3);
      color: var(--red);
    }
    .defense-banner--warn {
      background: var(--amber-dim); border: 1px solid rgba(251,191,36,0.3);
      color: var(--amber);
    }
    .defense-banner-icon { font-size: 1rem; flex-shrink: 0; margin-top: 0.05rem; }
    .defense-banner-body strong { display: block; font-weight: 600; margin-bottom: 0.15rem; }
    .defense-banner-body span { font-size: 0.78rem; opacity: 0.85; }

    /* Markdown */
    .chat-msg-bubble p { margin-bottom: 0.5rem; }
    .chat-msg-bubble p:last-child { margin-bottom: 0; }
    .chat-msg-bubble code {
      font-family: 'Courier New', monospace; font-size: 0.83em;
      background: rgba(255,255,255,0.06); padding: 0.1em 0.3em; border-radius: 3px;
    }
    .chat-msg-bubble pre {
      background: rgba(0,0,0,0.4); border: 1px solid var(--border);
      border-radius: 8px; padding: 0.75rem; overflow-x: auto; margin: 0.5rem 0;
    }
    .chat-msg-bubble pre code { background: none; padding: 0; }
    .chat-msg-bubble ul, .chat-msg-bubble ol { padding-left: 1.35rem; margin-bottom: 0.5rem; }
    .chat-msg-bubble li { margin-bottom: 0.2rem; }
    .chat-msg-bubble a { color: var(--teal); }
    .chat-msg-bubble h1, .chat-msg-bubble h2, .chat-msg-bubble h3 {
      font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 700;
      color: var(--white); margin: 0.5rem 0 0.25rem;
    }
    .chat-msg-bubble strong { color: var(--white); font-weight: 600; }
    .chat-msg-bubble blockquote {
      border-left: 3px solid var(--teal); padding-left: 0.75rem;
      color: var(--muted); margin: 0.35rem 0;
    }
    .chat-msg-bubble table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.85em; }
    .chat-msg-bubble th, .chat-msg-bubble td { border: 1px solid var(--border); padding: 0.35rem 0.6rem; }
    .chat-msg-bubble th { background: var(--surface-2); color: var(--white); font-weight: 600; }

    /* Typing cursor */
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
    .conv-typing-cursor {
      display: inline-block; width: 2px; height: 0.9em;
      background: var(--teal); margin-left: 2px; vertical-align: text-bottom;
      animation: blink 0.9s ease-in-out infinite;
    }
    /* Progress steps */
    .conv-stream-progress { list-style: none; padding: 0; margin: 0; }
    .conv-stream-progress-row {
      display: flex; align-items: flex-start; gap: 0.5rem;
      font-size: 0.82rem; color: var(--muted); padding: 0.2rem 0;
    }
    .conv-stream-progress-row strong { color: var(--text); font-weight: 500; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .conv-stream-progress-spin {
      display: inline-block; width: 10px; height: 10px;
      border: 1.5px solid var(--teal); border-top-color: transparent;
      border-radius: 50%; animation: spin 0.7s linear infinite;
      margin-top: 1px; flex-shrink: 0;
    }
    /* Action card */
    .conv-action-card {
      margin-top: 0.5rem; padding: 0.6rem 0.75rem;
      border-radius: 8px; background: var(--surface-2);
      border: 1px solid var(--border); font-size: 0.82rem;
    }
    .conv-action-card-title { font-weight: 600; color: var(--text); margin-bottom: 0.2rem; }
    .conv-action-card-summary { color: var(--muted); }

    /* Composer */
    .chat-composer-outer {
      flex-shrink: 0;
      padding: 0.5rem 0.75rem calc(0.5rem + env(safe-area-inset-bottom, 0px));
      border-top: 1px solid var(--border);
      background: rgba(7,8,10,0.92); backdrop-filter: blur(12px);
    }
    .chat-composer {
      display: flex; align-items: flex-end; gap: 0;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; overflow: hidden;
    }
    .chat-composer:focus-within { border-color: rgba(0,212,170,0.35); }
    .chat-agent-select {
      flex-shrink: 0; height: 44px;
      padding: 0 1.4rem 0 0.7rem;
      background: transparent; border: none; border-right: 1px solid var(--border);
      color: var(--muted); font-family: inherit; font-size: 0.78rem; font-weight: 500;
      cursor: pointer; outline: none; max-width: 155px;
      appearance: none; -webkit-appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%237a7f8e' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
      background-repeat: no-repeat; background-position: right 0.45rem center;
    }
    .chat-agent-select option { background: #111318; color: var(--text); }
    .chat-textarea {
      flex: 1; min-height: 44px; max-height: calc(4 * 1.45rem + 28px);
      padding: 0.6rem 0.5rem;
      background: transparent; border: none;
      color: var(--text); font-family: inherit; font-size: 0.92rem;
      line-height: 1.45; resize: none; outline: none; overflow-y: auto;
    }
    .chat-textarea::placeholder { color: var(--muted-2); font-size: 0.82rem; }
    .chat-send-btn {
      flex-shrink: 0; width: 44px; height: 44px;
      border: none; border-left: 1px solid var(--border);
      background: transparent; color: var(--teal);
      cursor: pointer;
      display: inline-flex; align-items: center; justify-content: center;
      transition: background 0.15s;
    }
    .chat-send-btn:hover:not(:disabled) { background: var(--teal-dim); }
    .chat-send-btn:disabled { opacity: 0.4; cursor: not-allowed; }
    .chat-send-btn svg { width: 17px; height: 17px; }
    .pwa-spinner {
      display: inline-block; width: 14px; height: 14px;
      border: 2px solid rgba(0,212,170,0.25); border-top-color: var(--teal);
      border-radius: 50%; animation: pwa-spin 0.7s linear infinite;
    }
  </style>
</head>
<body>

<!-- ── BOOT SPLASH ── -->
<div id="bootView">
  <div style="text-align:center">
    <div class="boot-brand">Cog<span>NEXUS</span></div>
    <div class="boot-sub" id="bootSub">Connecting&hellip;</div>
    <div class="boot-spinner"></div>
  </div>
</div>

<!-- ── LOGIN FALLBACK ── -->
<div id="loginView" hidden>
  <div class="login-card">
    <div class="login-brand">Cog<span>NEXUS</span></div>
    <div class="login-subtitle">Sign in to your workspace</div>
    <div class="login-field">
      <label for="loginEmail">Email</label>
      <input type="email" id="loginEmail" autocomplete="email" placeholder="you@example.com" />
    </div>
    <div class="login-field">
      <label for="loginPassword">Password</label>
      <input type="password" id="loginPassword" autocomplete="current-password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" />
    </div>
    <button class="login-btn" id="loginBtn">Sign in</button>
    <div class="login-error" id="loginError"></div>
    <div class="login-origin">Connected to <strong>__COGNEXUS_ORIGIN__</strong></div>
  </div>
</div>

<!-- ── CHAT VIEW ── -->
<div id="chatView" hidden>
  <header class="chat-header">
    <div class="chat-brand">Artzain <span>Chat</span><span style="font-size:0.62rem;color:#7a7f8e;border:1px solid #2a2f3a;border-radius:4px;padding:0.1rem 0.35rem;margin-left:0.5rem;vertical-align:middle;letter-spacing:0.04em;">LOCAL</span></div>
    <div class="chat-header-actions">
      <a href="__COGNEXUS_ORIGIN__/dashboard.html" target="_blank" rel="noopener" style="font-size:0.78rem;color:#7a7f8e;text-decoration:none;">Dashboard &#8599;</a>
      <span class="chat-user-email" id="chatUserEmail"></span>
      <button class="chat-new-btn" id="chatNewBtn" title="New conversation">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" width="14" height="14">
          <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
        New chat
      </button>
      <button class="chat-signout-btn" id="chatSignoutBtn">Sign out</button>
    </div>
  </header>

  <div class="chat-agents-hint">
    <span class="chat-agents-hint-label">Route to:</span>
    <button class="chat-agent-pill active" data-agent="">Contact Engine</button>
    <button class="chat-agent-pill" data-agent="legal">@legalAgent</button>
    <button class="chat-agent-pill" data-agent="propensity">@propensityAgent</button>
    <button class="chat-agent-pill" data-agent="compliance">@complianceMonitor</button>
    <button class="chat-agent-pill" data-agent="codebastion">@codeBastion</button>
  </div>

  <div class="chat-thread-wrap" id="chatThread"></div>

  <div class="chat-composer-outer">
    <div class="chat-composer">
      <select class="chat-agent-select" id="agentSelect" title="Active agent">
        <option value="">Contact Engine</option>
        <option value="legal">Legal Agent</option>
        <option value="propensity">Propensity Agent</option>
        <option value="compliance">Compliance Monitor</option>
        <option value="codebastion">Code Bastion</option>
      </select>
      <textarea
        class="chat-textarea"
        id="chatTextarea"
        rows="1"
        placeholder="Ask anything&hellip;  use @legalAgent / @propensityAgent / @complianceMonitor / @codeBastion"
      ></textarea>
      <button class="chat-send-btn" id="chatSendBtn" aria-label="Send">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
    </div>
  </div>
</div>

<script>
(function () {
  'use strict';

  const TOKEN_KEY = 'artzain_gui_token';
  const EMAIL_KEY = 'artzain_gui_email';

  function getToken()  { try { return localStorage.getItem(TOKEN_KEY) || ''; }  catch { return ''; } }
  function setToken(t) { try { localStorage.setItem(TOKEN_KEY, t); }             catch {} }
  function getEmail()  { try { return localStorage.getItem(EMAIL_KEY) || ''; }  catch { return ''; } }
  function setEmail(e) { try { localStorage.setItem(EMAIL_KEY, e); }             catch {} }
  function clearAuth() { try { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(EMAIL_KEY); } catch {} }
  function authHeaders() {
    const t = getToken();
    return t ? { 'Authorization': 'Bearer ' + t } : {};
  }

  // DOM refs
  const bootView      = document.getElementById('bootView');
  const bootSub       = document.getElementById('bootSub');
  const loginView     = document.getElementById('loginView');
  const chatView      = document.getElementById('chatView');
  const loginEmailEl  = document.getElementById('loginEmail');
  const loginPwEl     = document.getElementById('loginPassword');
  const loginBtn      = document.getElementById('loginBtn');
  const loginError    = document.getElementById('loginError');
  const chatUserEmail = document.getElementById('chatUserEmail');
  const chatNewBtn    = document.getElementById('chatNewBtn');
  const chatSignoutBtn= document.getElementById('chatSignoutBtn');
  const threadEl      = document.getElementById('chatThread');
  const ta            = document.getElementById('chatTextarea');
  const sendBtn       = document.getElementById('chatSendBtn');
  const agentSel      = document.getElementById('agentSelect');

  let activeConvId = null;
  let sending = false;

  // ── Views ──────────────────────────────────────────────────────────────────

  function hideBoot()  { bootView.hidden = true; }
  function showLogin() {
    hideBoot(); loginView.hidden = false; chatView.hidden = true;
    loginError.textContent = '';
    setTimeout(() => loginEmailEl.focus(), 120);
  }
  function showChat(emailOrName) {
    hideBoot(); loginView.hidden = true; chatView.hidden = false;
    chatUserEmail.textContent = emailOrName || getEmail();
    setTimeout(() => ta.focus(), 200);
  }
  function unauthorizedHandler() {
    clearAuth(); activeConvId = null; showLogin();
  }

  // ── Login (fallback when no API key) ──────────────────────────────────────

  async function doLogin() {
    const email = loginEmailEl.value.trim();
    const pw    = loginPwEl.value;
    if (!email || !pw) { loginError.textContent = 'Please enter your email and password.'; return; }
    loginBtn.disabled = true; loginBtn.textContent = 'Signing in\u2026'; loginError.textContent = '';
    try {
      const res  = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pw }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.token) {
        setToken(data.token); setEmail(email);
        showChat(email); await ensureConversation();
      } else {
        loginError.textContent = data.detail || data.message || 'Login failed \u2014 check your credentials.';
      }
    } catch { loginError.textContent = 'Connection error. Is the CogNEXUS server reachable?'; }
    finally { loginBtn.disabled = false; loginBtn.textContent = 'Sign in'; }
  }

  loginBtn.addEventListener('click', doLogin);
  loginEmailEl.addEventListener('keydown', e => { if (e.key === 'Enter') loginPwEl.focus(); });
  loginPwEl.addEventListener('keydown',    e => { if (e.key === 'Enter') doLogin(); });
  chatSignoutBtn.addEventListener('click', () => { clearAuth(); activeConvId = null; setQuickstartThread(); showLogin(); });

  // ── Agent pills ────────────────────────────────────────────────────────────

  document.querySelectorAll('.chat-agent-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.chat-agent-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      agentSel.value = pill.dataset.agent;
      ta.focus();
    });
  });

  agentSel.addEventListener('change', () => {
    const v = agentSel.value;
    document.querySelectorAll('.chat-agent-pill').forEach(p => {
      p.classList.toggle('active', p.dataset.agent === v);
    });
  });

  // ── Conversations ──────────────────────────────────────────────────────────

  const QUICKSTART_PROMPTS = [
    { icon: '\\u{1F50C}', label: 'Connectors', text: 'Which connectors are currently active in my workspace?' },
    { icon: '\\u{1F4C8}', label: 'Propensity', text: '@propensityAgent Which deals in my pipeline are most likely to close this quarter?' },
    { icon: '\\u{1F6E1}\\u{FE0F}', label: 'Compliance', text: '@complianceMonitor Check for policy compliance issues in the last 7 days and summarise findings.' },
    { icon: '\\u{2696}\\u{FE0F}', label: 'Legal', text: '@legalAgent Draft a one-page NDA summary for a new vendor partnership.' },
    { icon: '\\u{1F9BA}', label: 'Code Review', text: '@codeBastion Review the latest authentication changes and flag any security risks.' },
    { icon: '\\u{1F4E5}', label: 'Churn Risk', text: 'Show me the top 10 customers at highest churn risk from the CRM data.' },
  ];

  function setQuickstartThread() {
    threadEl.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'quickstart-wrap';
    wrap.innerHTML = `
      <div class="quickstart-brand">Cog<span>NEXUS</span></div>
      <div class="quickstart-tagline">Ask anything, or try a quickstart below</div>
      <div class="quickstart-grid" id="quickstartGrid"></div>
    `;
    threadEl.appendChild(wrap);
    const grid = wrap.querySelector('#quickstartGrid');
    QUICKSTART_PROMPTS.forEach(p => {
      const btn = document.createElement('button');
      btn.className = 'quickstart-chip';
      btn.innerHTML = `<span class="quickstart-chip-icon">${p.icon}</span><span><div class="quickstart-chip-label">${esc(p.label)}</div>${esc(p.text)}</span>`;
      btn.addEventListener('click', () => {
        ta.value = p.text;
        autoResize();
        setTimeout(() => { ta.focus(); sendMessage(); }, 60);
      });
      grid.appendChild(btn);
    });
  }

  async function ensureConversation() {
    try {
      const res = await fetch('/api/conversations', { headers: authHeaders() });
      if (res.status === 401) { unauthorizedHandler(); return; }
      if (!res.ok) return;
      const data = await res.json();
      const list = (data.conversations || []).sort(
        (a, b) => new Date(b.updated_at || 0) - new Date(a.updated_at || 0)
      );
      if (list.length) {
        activeConvId = list[0].id;
        await loadMessages(activeConvId);
      } else {
        await createNewConversation(true);
      }
    } catch {}
  }

  async function createNewConversation(silent) {
    if (!silent && sending) return;
    try {
      const res = await fetch('/api/conversations', {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'New Conversation' }),
      });
      if (res.status === 401) { unauthorizedHandler(); return; }
      if (!res.ok) return;
      const row = await res.json();
      activeConvId = row.id;
      setQuickstartThread();
      ta.value = ''; autoResize(); scrollThread();
      setTimeout(() => ta.focus(), 50);
    } catch {}
  }

  chatNewBtn.addEventListener('click', () => createNewConversation(false));

  async function loadMessages(convId) {
    threadEl.innerHTML = '';
    try {
      const res = await fetch(`/api/conversations/${convId}/messages`, { headers: authHeaders() });
      if (res.status === 401) { unauthorizedHandler(); return; }
      if (!res.ok) return;
      const data = await res.json();
      if (!data.messages || !data.messages.length) { setQuickstartThread(); return; }
      data.messages.forEach(m => appendMessage(m));
      scrollThread();
    } catch {}
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function renderMarkdown(text) {
    if (!text) return '';
    try {
      if (typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined') {
        const renderer = new marked.Renderer();
        renderer.link = function(href, title, text) {
          const h  = typeof href === 'object' ? (href.href  || '') : (href  || '');
          const ti = typeof href === 'object' ? (href.title || '') : (title || '');
          const tx = typeof href === 'object' ? (href.text  || h) : (text  || h);
          return `<a href="${h}"${ti ? ` title="${ti}"` : ''} target="_blank" rel="noopener noreferrer">${tx}</a>`;
        };
        const html = marked.parse(text, { renderer, breaks: true, gfm: true });
        return DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'rel'] });
      }
    } catch {}
    return esc(text).replace(/\\n/g, '<br>');
  }

  function fmtClock(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
    catch { return ''; }
  }

  function agentLabel(key) {
    const MAP = { legal: 'Legal Agent', propensity: 'Propensity Agent', compliance: 'Compliance Monitor', codebastion: 'Code Bastion' };
    return MAP[key] || 'Context Engine';
  }

  function scrollThread() { threadEl.scrollTo({ top: threadEl.scrollHeight, behavior: 'smooth' }); }

  function autoResize() {
    ta.style.height = 'auto';
    const lh = parseFloat(getComputedStyle(ta).lineHeight) || 23;
    ta.style.height = Math.min(ta.scrollHeight, lh * 4 + 28) + 'px';
  }

  function buildActionCard(card) {
    const div = document.createElement('div');
    div.className = 'conv-action-card';
    const st = card.status || 'pending';
    div.innerHTML = `
      ${card.action_title ? `<div class="conv-action-card-title">${esc(card.action_title)}</div>` : ''}
      <div class="conv-action-card-summary">${esc(card.summary || '')}</div>
      <div style="margin-top:0.3rem;font-size:0.65rem;color:var(--muted)">${esc(st)}</div>
    `;
    return div;
  }

  function appendMessage(msg, streaming) {
    const role = msg.role;
    const wrap = document.createElement('div');
    wrap.className = 'chat-msg'; wrap.dataset.msgId = msg.id || '';

    if (role === 'system') {
      wrap.classList.add('chat-msg--system');
      wrap.innerHTML = `<div class="chat-msg-bubble">${esc(msg.content)}</div>`;
      threadEl.appendChild(wrap); return wrap;
    }

    const isUser = role === 'user';
    wrap.classList.add(isUser ? 'chat-msg--user' : 'chat-msg--assistant');
    const sender      = isUser ? 'You' : agentLabel(msg.agent);
    const contentHtml = streaming ? '<span class="conv-typing-cursor"></span>' : renderMarkdown(msg.content);
    const hideBubble  = !streaming && !((msg.content || '').trim()) && msg.action_card;
    wrap.innerHTML = `
      <div class="chat-msg-sender">${esc(sender)}</div>
      <div class="chat-msg-bubble"${hideBubble ? ' style="display:none"' : ''}>${contentHtml}</div>
      ${msg.created_at ? `<div class="chat-msg-time">${esc(fmtClock(msg.created_at))}</div>` : ''}
    `;
    if (msg.action_card) wrap.appendChild(buildActionCard(msg.action_card));
    threadEl.appendChild(wrap); return wrap;
  }

  function insertDefenseBanner(isBlocked, threatLevel, explanation, injType) {
    const banner = document.createElement('div');
    banner.className = `defense-banner ${isBlocked ? 'defense-banner--blocked' : 'defense-banner--warn'}`;
    const icon  = isBlocked ? '\\u{1F6AB}' : '\\u26A0\\uFE0F';
    const title = isBlocked
      ? 'Prompt injection blocked'
      : `Prompt injection detected \u2014 ${threatLevel || 'medium'} risk`;
    const detail = explanation
      ? explanation.slice(0, 180) + (explanation.length > 180 ? '\\u2026' : '')
      : (injType ? `Detected pattern: ${injType}` : 'Input contains potentially adversarial content.');
    banner.innerHTML = `
      <div class="defense-banner-icon">${icon}</div>
      <div class="defense-banner-body"><strong>${esc(title)}</strong><span>${esc(detail)}</span></div>
    `;
    threadEl.appendChild(banner);
    scrollThread();
    return banner;
  }

  // ── Agent mention detection ────────────────────────────────────────────────

  function detectAgentMention(text) {
    const m = text.match(/@(legal(?:\\s*agent)?|propensity(?:\\s*(?:agent|oracle))?|compliance(?:\\s*monitor)?|code\\s*bas(?:t|s)ion)/i);
    if (!m) return null;
    const raw = m[1].toLowerCase().replace(/\\s+/g, '');
    const MAP = {
      legal: 'legal', legalagent: 'legal',
      propensity: 'propensity', propensityagent: 'propensity', propensityoracle: 'propensity',
      compliance: 'compliance', compliancemonitor: 'compliance',
      codebastion: 'codebastion', codebaston: 'codebastion',
    };
    return MAP[raw] || null;
  }

  // ── Send message ───────────────────────────────────────────────────────────

  async function sendMessage() {
    if (sending || !activeConvId) return;
    const content = ta.value.trim();
    if (!content) return;

    const agent = agentSel.value || detectAgentMention(content) || null;

    // ── 1. Prompt-defence screen ───────────────────────────────────────────
    let defenseBlocked = false;
    try {
      const sr = await fetch('/gui/screen', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      if (sr.ok) {
        const sd = await sr.json();
        if (sd.is_injection) {
          insertDefenseBanner(sd.should_block, sd.threat_level, sd.explanation, sd.injection_type);
          if (sd.should_block) {
            defenseBlocked = true;
          }
        }
      }
    } catch {}

    if (defenseBlocked) return;

    // ── 2. Send to platform ────────────────────────────────────────────────
    sending = true;
    sendBtn.disabled = chatNewBtn.disabled = true;
    sendBtn.innerHTML = '<span class="pwa-spinner" aria-hidden="true"></span>';
    ta.value = ''; autoResize();

    // Remove quickstart chips if present
    const qs = threadEl.querySelector('.quickstart-wrap');
    if (qs) qs.remove();

    appendMessage({ role: 'user', content, created_at: new Date().toISOString(), id: 'tmp-' + Date.now() });
    if (agent) appendMessage({ role: 'system', content: agentLabel(agent) + ' is working on this\u2026' });

    const streamWrap = appendMessage({ role: 'assistant', content: '', agent }, true);
    const bubble     = streamWrap?.querySelector('.chat-msg-bubble');
    scrollThread();

    let fullText = '';
    const progressSteps = [];
    let tickerId = null;

    function renderProgress() {
      if (!bubble || !progressSteps.length) return;
      const now = performance.now();
      const rows = progressSteps.map((s, i) => {
        const done    = i < progressSteps.length - 1;
        const icon    = done ? '<span style="color:var(--teal);font-size:0.8rem">\\u2713</span>' : '<span class="conv-stream-progress-spin"></span>';
        const elapsed = done ? ((s.endedAt || now) - s.startedAt) : (now - s.startedAt);
        const dur     = elapsed < 60000 ? (elapsed / 1000).toFixed(1) + 's' : Math.floor(elapsed / 60000) + ':' + String(Math.floor((elapsed % 60000) / 1000)).padStart(2, '0');
        const det     = s.detail ? `<div style="font-size:0.72rem;color:var(--muted-2);margin-top:0.1rem">${esc(s.detail)}</div>` : '';
        return `<li class="conv-stream-progress-row">${icon}<div><strong>${esc(s.label)}</strong> \\u00b7 ${esc(dur)}${det}</div></li>`;
      }).join('');
      bubble.innerHTML = `<ul class="conv-stream-progress">${rows}</ul><span class="conv-typing-cursor" style="display:inline-block;margin-top:0.35rem"></span>`;
      scrollThread();
    }
    function stopTicker() { if (tickerId != null) { clearInterval(tickerId); tickerId = null; } }

    try {
      const res = await fetch(`/api/conversations/${activeConvId}/messages`, {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, agent }),
      });
      if (res.status === 401) { unauthorizedHandler(); return; }
      if (!res.ok) {
        stopTicker();
        if (bubble) bubble.innerHTML = '<em style="color:var(--red)">Error \u2014 please try again.</em>';
        return;
      }

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'progress') {
              const t = performance.now();
              if (progressSteps.length) progressSteps[progressSteps.length - 1].endedAt = t;
              progressSteps.push({ label: evt.label || 'Working', detail: evt.detail || '', startedAt: t, endedAt: null });
              if (!tickerId) tickerId = setInterval(renderProgress, 250);
              renderProgress();
            } else if (evt.type === 'token') {
              if (progressSteps.length && fullText === '') { stopTicker(); progressSteps.length = 0; }
              fullText += evt.text;
              if (bubble) {
                bubble.innerHTML = renderMarkdown(fullText) + '<span class="conv-typing-cursor" style="display:inline-block"></span>';
                scrollThread();
              }
            } else if (evt.type === 'done') {
              stopTicker();
              if (bubble) {
                if (!fullText.trim() && evt.action_card) bubble.style.display = 'none';
                else bubble.innerHTML = renderMarkdown(fullText);
              }
              const tw = document.createElement('div');
              tw.className = 'chat-msg-time'; tw.textContent = fmtClock(new Date().toISOString());
              streamWrap.appendChild(tw);
              if (evt.action_card && streamWrap) streamWrap.appendChild(buildActionCard(evt.action_card));
            }
          } catch {}
        }
      }
    } catch {
      if (bubble) bubble.innerHTML = '<em style="color:var(--red)">Connection error \u2014 please try again.</em>';
    } finally {
      stopTicker();
      sending = false;
      sendBtn.disabled = chatNewBtn.disabled = false;
      sendBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" stroke-linecap="round" stroke-linejoin="round"/></svg>';
      scrollThread(); setTimeout(() => ta.focus(), 50);
    }
  }

  ta.addEventListener('input', autoResize);
  ta.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });
  sendBtn.addEventListener('click', sendMessage);

  // ── Boot ───────────────────────────────────────────────────────────────────

  async function boot() {
    // 1. Try API-key bootstrap (no login needed)
    try {
      const res = await fetch('/gui/bootstrap');
      if (res.ok) {
        const d = await res.json();
        if (d.token) {
          setToken(d.token); setEmail(d.email || d.display_name || '');
          showChat(d.display_name || d.email || '');
          await ensureConversation(); return;
        }
      }
    } catch {}

    // 2. Try stored token
    const stored = getToken();
    if (stored) {
      try {
        const r = await fetch('/api/auth/me', { headers: authHeaders() });
        if (r.ok) {
          const me = await r.json().catch(() => ({}));
          setEmail(me.email || getEmail());
          showChat(me.email || getEmail());
          await ensureConversation(); return;
        }
      } catch {}
      clearAuth();
    }

    // 3. Fall back to login form
    bootSub.textContent = 'No API key found \u2014 please sign in.';
    setTimeout(showLogin, 600);
  }

  boot();
})();
</script>
</body>
</html>
"""


# ──────────────────────────────────────────────────────────────────────────────
# Proxy server
# ──────────────────────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _try_bootstrap(upstream: str, api_key: str) -> dict[str, str] | None:
    """Exchange *api_key* for a JWT via ``POST /api/auth/token``.

    Returns ``{token, email, display_name}`` or *None* on failure.
    """
    parts  = urllib.parse.urlsplit(upstream)
    origin = f"{parts.scheme}://{parts.netloc}"
    url    = upstream.rstrip("/") + "/api/auth/token"
    req    = urllib.request.Request(
        url,
        data=b"{}",
        headers={
            "X-Api-Key":       api_key,
            "Content-Type":    "application/json",
            "Accept":          "application/json",
            "User-Agent":      _DEFAULT_BROWSER_UA,
            "Origin":          origin,
            "Referer":         origin + "/",
            "Sec-Fetch-Dest":  "empty",
            "Sec-Fetch-Mode":  "cors",
            "Sec-Fetch-Site":  "same-origin",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            if data.get("token"):
                return data
    except Exception:  # noqa: BLE001
        pass
    return None


def _screen_message(content: str) -> dict[str, Any]:
    """Run local prompt-injection screening via the artzain SDK."""
    try:
        from artzain import screen_user_input, should_block  # type: ignore[import]
        result      = screen_user_input(content, source="gui")
        tl          = result.threat_level
        threat_str  = tl.value if hasattr(tl, "value") else str(tl)
        inj_raw     = getattr(result, "injection_type", None)
        inj_str     = (inj_raw.value if hasattr(inj_raw, "value") else str(inj_raw)) if inj_raw else ""
        expl        = getattr(result, "explanation", "") or ""
        return {
            "is_injection":   bool(result.is_injection),
            "should_block":   bool(should_block(result)),
            "threat_level":   threat_str,
            "explanation":    str(expl),
            "injection_type": inj_str,
        }
    except Exception:  # noqa: BLE001
        return {"is_injection": False, "should_block": False, "threat_level": "none", "explanation": "", "injection_type": ""}


def _make_handler(base_url: str, html_bytes: bytes, api_key: str) -> type[BaseHTTPRequestHandler]:
    """Return a request-handler class closed over the server configuration."""
    upstream = base_url.rstrip("/")
    parts    = urllib.parse.urlsplit(upstream)
    origin   = f"{parts.scheme}://{parts.netloc}"

    # Cached bootstrap result shared across all handler instances.
    _cache: dict[str, Any] = {}

    class _Handler(BaseHTTPRequestHandler):
        server_version = "ArtzainChat/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ANN001
            pass

        # ── HTML ──────────────────────────────────────────────────────────

        def _serve_html(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html_bytes)

        # ── JSON helper ───────────────────────────────────────────────────

        def _serve_json(self, status: int, data: dict[str, Any]) -> None:
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        # ── API proxy ─────────────────────────────────────────────────────

        def _proxy(self, method: str, body: bytes | None = None) -> None:
            url = upstream + self.path

            fwd: dict[str, str] = {
                # Forward the browser UA so the upstream WAF accepts the request.
                "User-Agent": (
                    self.headers.get("user-agent") or _DEFAULT_BROWSER_UA
                ),
                # Rewrite Origin/Referer from localhost → upstream domain.
                "Origin":          origin,
                "Referer":         origin + "/",
                "Sec-Fetch-Dest":  "empty",
                "Sec-Fetch-Mode":  "cors",
                "Sec-Fetch-Site":  "same-origin",
                "Accept-Language": (self.headers.get("accept-language") or "en-US,en;q=0.9"),
            }
            for hdr in ("authorization", "content-type", "accept", "x-request-id"):
                v = self.headers.get(hdr)
                if v:
                    fwd[hdr] = v

            is_sse = method == "POST" and "messages" in self.path and "conversations" in self.path
            timeout = 300.0 if is_sse else 30.0

            req = urllib.request.Request(url, data=body, headers=fwd, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in _HOP_BY_HOP:
                            self.send_header(k, v)
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    if is_sse:
                        while chunk := resp.read(256):
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    else:
                        self.wfile.write(resp.read())
            except urllib.error.HTTPError as exc:
                payload = exc.read()
                self.send_response(exc.code)
                self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).encode()
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

        # ── Local GUI endpoints ───────────────────────────────────────────

        def _handle_gui_bootstrap(self) -> None:
            """Exchange the stored API key for a JWT and return it to the browser."""
            if not api_key:
                self._serve_json(200, {"token": None, "error": "No API key configured."})
                return

            # Re-use cached token (valid for 30 days; refresh after 24 h of uptime).
            cached = _cache.get("bootstrap")
            if cached and (time.time() - _cache.get("bootstrap_ts", 0)) < 86400:
                self._serve_json(200, cached)
                return

            result = _try_bootstrap(upstream, api_key)
            if result:
                _cache["bootstrap"]    = result
                _cache["bootstrap_ts"] = time.time()
                self._serve_json(200, result)
            else:
                self._serve_json(200, {"token": None, "error": "Could not exchange API key for session token."})

        def _handle_gui_screen(self, body: bytes) -> None:
            """Run local prompt-defence screening and return the result."""
            try:
                payload = json.loads(body) if body else {}
                content = str(payload.get("content", ""))
            except Exception:  # noqa: BLE001
                content = ""
            result = _screen_message(content)
            self._serve_json(200, result)

        # ── HTTP verb handlers ────────────────────────────────────────────

        def do_GET(self) -> None:
            if self.path == "/gui/bootstrap":
                self._handle_gui_bootstrap()
            elif self.path.startswith("/dashboard"):
                # The hosted dashboard is not served here — send the browser
                # to the platform instead of echoing the chat page back.
                self.send_response(302)
                self.send_header("Location", f"{base_url}/dashboard.html")
                self.end_headers()
            elif not self.path.startswith("/api/"):
                self._serve_html()
            else:
                self._proxy("GET")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b""
            if self.path == "/gui/screen":
                self._handle_gui_screen(body)
            else:
                self._proxy("POST", body)

        def do_DELETE(self) -> None:
            self._proxy("DELETE")

        def do_PUT(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b""
            self._proxy("PUT", body)

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.end_headers()

    return _Handler


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def launch_gui(
    base_url: str,
    *,
    api_key: str = "",
    port: int | None = None,
    no_browser: bool = False,
) -> None:
    """Start the local GUI proxy and open it in the default browser.

    Blocks until the user presses **Ctrl-C**.

    Parameters
    ----------
    base_url:
        CogNEXUS platform origin, e.g. ``https://app.cognexuslabs.ai``.
    api_key:
        Dashboard API key (``COGNEXUS_API_KEY``).  When present the browser
        goes straight to the chat — no login form shown.
    port:
        Local TCP port.  A random free port is chosen when *None*.
    no_browser:
        If *True* start the server without opening a browser tab.
    """
    if port is None:
        port = _find_free_port()

    html_bytes = _GUI_HTML_TEMPLATE.replace("__COGNEXUS_ORIGIN__", base_url).encode("utf-8")
    handler_cls = _make_handler(base_url, html_bytes, api_key)
    server      = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    local_url   = f"http://127.0.0.1:{port}"

    key_hint = f"  API key      \u2192  {api_key[:8]}\u2026 (auto-login enabled)" if api_key else "  API key      \u2192  not set (login form will show)"

    print()
    print(f"  Artzain Chat (local)  \u2192  {local_url}")
    print(f"  Platform API          \u2192  {base_url}")
    print(f"  Full dashboard        \u2192  {base_url}/dashboard.html (hosted \u2014 not this local server)")
    print(key_hint)
    print("  Press Ctrl-C to quit.")
    print()

    if not no_browser:
        def _open() -> None:
            time.sleep(0.5)
            webbrowser.open(local_url)
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Artzain Chat stopped.")
    finally:
        server.shutdown()
