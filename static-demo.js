// Browse-only layer for the recorded demo. Answers the app's /api requests from
// files saved by scripts/build-static.mjs, so no server, key or model is needed.
// Anything that would upload, approve or start work is turned off.
//
// If scripts/encrypt-static.mjs has run, every file is encrypted (AES-GCM, key
// from a passphrase through PBKDF2) and stored under a hashed name; the page asks
// for the passphrase before loading anything.

const NOTE = 'This is a browse-only demo with recorded results. Uploading, approving and running are turned off.';
const realFetch = window.fetch.bind(window);
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

let toastTimer;
function toast(text) {
  let t = document.getElementById('demoToast');
  if (!t) { t = document.createElement('div'); t.id = 'demoToast'; document.body.append(t); }
  t.textContent = text; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 3800);
}

// ── Storage: plain files, or encrypted files behind a passphrase ────────────
const meta = await realFetch('enc.json').then(r => r.ok ? r.json() : null).catch(() => null);
let read; // logical path -> ArrayBuffer | null

if (meta) {
  const key = await unlock(meta);
  read = async path => {
    const name = hex(await crypto.subtle.digest('SHA-256', enc.encode(`${meta.salt}:${path}`)));
    const r = await realFetch(`x/${name}`);
    if (!r.ok) return null;
    const buf = await r.arrayBuffer();
    return crypto.subtle.decrypt({name: 'AES-GCM', iv: buf.slice(0, 12)}, key, buf.slice(12));
  };
} else {
  read = async path => { const r = await realFetch(path); return r.ok ? r.arrayBuffer() : null; };
}

async function deriveKey(passphrase, m) {
  const material = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt: b64(m.salt), iterations: m.iterations},
    material, {name: 'AES-GCM', length: 256}, true, ['decrypt']);
}
async function works(key, m) {
  const c = b64(m.check);
  try { return dec.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: c.slice(0, 12)}, key, c.slice(12))) === 'glass-demo-ok'; } catch { return false; }
}
async function unlock(m) {
  // Remembered for this tab only, so a reload does not ask again.
  try {
    const saved = sessionStorage.getItem('demoKey');
    if (saved) {
      const key = await crypto.subtle.importKey('raw', b64(saved), 'AES-GCM', true, ['decrypt']);
      if (await works(key, m)) return key;
    }
  } catch {}
  const gate = document.createElement('div');
  gate.id = 'demoGate';
  gate.innerHTML = `<form><span class="mark"><i></i></span><h1>Recorded demo</h1>
    <p>Enter the passphrase you were given.</p>
    <input type="password" autocomplete="current-password" aria-label="Passphrase" required autofocus>
    <button class="btn" type="submit">Open</button><p class="err" role="alert"></p></form>`;
  document.body.append(gate);
  const form = gate.querySelector('form'), input = gate.querySelector('input'), err = gate.querySelector('.err'), btn = gate.querySelector('button');
  input.focus();
  return new Promise(resolve => {
    form.onsubmit = async e => {
      e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = 'Opening…';
      const key = await deriveKey(input.value, m);
      if (await works(key, m)) {
        try { sessionStorage.setItem('demoKey', btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', key))))); } catch {}
        gate.remove(); resolve(key);
      } else { err.textContent = 'That passphrase did not work.'; btn.disabled = false; btn.textContent = 'Open'; input.select(); }
    };
  });
}

const manifest = JSON.parse(dec.decode(await read('data/manifest.json')));

// ── The app's requests ──────────────────────────────────────────────────────
// Matches scripts/build-static.mjs: a query is folded into the file name.
const jsonPath = u => { const [p, q] = u.split('?'); return `data/${p.replace(/^\/api\//, '')}${q ? '__' + q.replace(/[=&]/g, '_') : ''}.json`; };
const json = (body, status) => new Response(JSON.stringify(body), {status, headers: {'Content-Type': 'application/json'}});

window.fetch = async (input, opts = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  if (!url.startsWith('/api/')) return realFetch(input, opts);
  if ((opts.method ?? 'GET').toUpperCase() !== 'GET') { toast(NOTE); return json({error: NOTE}, 403); }
  const file = manifest[url];
  const body = await read(file?.path ?? jsonPath(url));
  return body ? new Response(body, {status: 200, headers: {'Content-Type': file?.type ?? 'application/json'}}) : json({error: 'Not included in this demo.'}, 404);
};

// The live app streams status over SSE; here one recorded status is sent once.
window.EventSource = class {
  constructor() {
    this.handlers = {};
    setTimeout(async () => {
      const data = await (await window.fetch('/api/status')).text();
      (this.handlers.status ?? []).forEach(f => f({data}));
    }, 0);
  }
  addEventListener(type, f) { (this.handlers[type] ??= []).push(f); }
  close() {}
};

// ── Downloads, PDFs and images ──────────────────────────────────────────────
const isFile = v => /\.[a-z]+(\?|$)|\/file$/.test(v);
const blobs = new Map();
async function blobUrl(url) {
  if (!blobs.has(url)) blobs.set(url, (async () => {
    const file = manifest[url];
    const body = await read(file?.path ?? jsonPath(url));
    return body ? URL.createObjectURL(new Blob([body], {type: file?.type ?? 'application/json'})) : null;
  })());
  return blobs.get(url);
}
// Links keep their original address in data-api and download on click.
function fix(el) {
  if (el.tagName === 'A') {
    const v = el.getAttribute('href');
    if (v?.startsWith('/api/')) { el.dataset.api = v; el.setAttribute('href', '#'); }
  }
  const src = el.getAttribute?.('src');
  if (src?.startsWith('/api/')) {
    el.removeAttribute('src');
    blobUrl(src).then(u => { if (u) el.setAttribute('src', u); });
  }
}
document.addEventListener('click', async e => {
  const a = e.target.closest?.('a[data-api]');
  if (!a) return;
  e.preventDefault();
  const url = a.dataset.api, u = await blobUrl(url);
  if (!u) return toast('That download is not included in this demo.');
  const file = manifest[url];
  const link = document.createElement('a');
  link.href = u;
  link.download = file?.name ?? a.getAttribute('download') ?? (url.split('/').pop().split('?')[0] + (isFile(url) ? '' : '.json'));
  link.click();
}, true);
new MutationObserver(list => {
  for (const m of list) {
    if (m.type === 'attributes') fix(m.target);
    else m.addedNodes.forEach(n => { if (n.nodeType === 1) { fix(n); n.querySelectorAll('[href^="/api/"],[src^="/api/"]').forEach(fix); } });
  }
}).observe(document.documentElement, {subtree: true, childList: true, attributes: true, attributeFilter: ['href', 'src']});

// ── No uploads ──────────────────────────────────────────────────────────────
document.addEventListener('click', e => {
  if (e.target.closest?.('input[type=file]')) { e.preventDefault(); e.stopPropagation(); toast(NOTE); }
}, true);
for (const type of ['dragover', 'drop']) window.addEventListener(type, e => {
  e.preventDefault(); e.stopPropagation();
  if (type === 'drop') toast(NOTE);
}, true);

const badge = document.createElement('div');
badge.id = 'demoBadge';
badge.textContent = 'Recorded demo · browse only';
badge.title = NOTE;
document.body.append(badge);

// ── Start the app ───────────────────────────────────────────────────────────
if (meta) {
  // Encrypted modules load as blobs, with their imports pointed at each other.
  document.title = manifest.$title ?? document.title;
  document.querySelectorAll('[data-brand]').forEach(el => { el.textContent = manifest.$brand ?? el.textContent; });
  const mod = async (path, swaps = {}) => {
    let code = dec.decode(await read(path));
    for (const [from, to] of Object.entries(swaps)) code = code.replaceAll(`'${from}'`, `'${to}'`);
    return URL.createObjectURL(new Blob([code], {type: 'text/javascript'}));
  };
  const confidence = await mod('confidence.js');
  const analytics = await mod('analytics.js', {'./confidence.js': confidence});
  await import(await mod('app.js', {'./analytics.js': analytics, './confidence.js': confidence}));
} else {
  await import('./app.js');
}
