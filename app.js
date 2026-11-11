// Clip — クリップ＆メモ。データは端末内とDropbox（アプリフォルダ）に保存。
const DEFAULT_APP_KEY = '83k9w84j8h7m2t4';
const DBX_JSON = '/clips.json';
const DBX_MD = '/clips.md';
const PBKDF2_ITER = 600000;

const $ = (s) => document.querySelector(s);
const LS = { items: 'clip.items', meta: 'clip.meta', tok: 'clip.dbx', key: 'clip.appkey', rev: 'clip.rev', pkce: 'clip.pkce', lock: 'clip.autolock', last: 'clip.lastsync' };
const KIND = { link: 'リンク', word: 'ワード', note: 'メモ' };
const SENSITIVE = /パスワード|password|passwd|\bpass\s*[:：]|\bPW\b|pw\s*[:：]|暗証|パス\s*[:：]|ログイン/i;

const load = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };

let items = load(LS.items, []);
let meta = load(LS.meta, {});
let vaultKey = null;
const plain = new Map(); // 鍵付きクリップの復号結果（メモリ内のみ）
const ui = { kind: '', tag: '', q: '', archive: false, secretNew: false };

/* ---------- utils ---------- */
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf) { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s); }
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const URL_RE = /https?:\/\/[^\s<>"'）」』】]+/;
const host = (u) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
const fmtDate = (t) => { const d = new Date(t); const n = new Date(); const p = (x) => String(x).padStart(2, '0'); return (d.getFullYear() === n.getFullYear() ? '' : d.getFullYear() + '/') + (d.getMonth() + 1) + '/' + d.getDate() + (d.toDateString() === n.toDateString() ? ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) : ''); };
const isoDate = (t) => { const d = new Date(t); const p = (x) => String(x).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; };
function svg(id) { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); const u = document.createElementNS('http://www.w3.org/2000/svg', 'use'); u.setAttribute('href', '#i-' + id); s.append(u); return s; }
function setIcon(btn, id) { btn.querySelector('use').setAttribute('href', '#i-' + id); }
let toastT;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(() => (t.hidden = true), 1800); }
async function copyText(s) { try { await navigator.clipboard.writeText(s); toast('コピーしました'); } catch { toast('コピーできませんでした'); } }

function kindOf({ title, text, url }) {
  if (url) return 'link';
  const full = [title, text].filter(Boolean).join('\n').trim();
  return !full.includes('\n') && full.length <= 30 ? 'word' : 'note';
}
function parseTags(s) { const tags = []; const rest = s.replace(/(^|\s)#([^\s#]+)/g, (m, sp, t) => { if (!tags.includes(t)) tags.push(t); return sp; }); return { tags, rest: rest.replace(/[ \t]+\n/g, '\n').trim() }; }
function parseInput(raw, extra = {}) {
  let { tags, rest } = parseTags(raw);
  let url = extra.url || '';
  if (!url) { const m = rest.match(URL_RE); if (m) url = m[0]; }
  if (url) rest = rest.split(url).join('').trim();
  let title = (extra.title || '').trim();
  let text = rest;
  if (title && text === title) text = '';
  if (url && !title && text && !text.includes('\n') && text.length <= 80) { title = text; text = ''; }
  const v = { title, text, url, tags };
  v.kind = kindOf(v);
  return v;
}

/* ---------- crypto ---------- */
async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, obj) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))); return { iv: b64(iv), ct: b64(ct) }; }
async function unseal(key, e) { const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, key, unb64(e.ct)); return JSON.parse(dec.decode(pt)); }
const hasVault = () => !!(meta && meta.salt && meta.check);

async function setupVault() {
  const pass = await askPass({ title: '合言葉を設定', confirm: true });
  if (!pass) return false;
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const key = await deriveKey(pass, salt);
  meta = { salt, check: await seal(key, 'clip') };
  save(LS.meta, meta);
  vaultKey = key;
  scheduleSync();
  updateLockBtn();
  return true;
}
async function unlock() {
  if (vaultKey) return true;
  if (!hasVault()) return setupVault();
  const pass = await askPass({ title: '合言葉', verify: async (p) => { const k = await deriveKey(p, meta.salt); await unseal(k, meta.check); return k; } });
  if (!pass) return false;
  vaultKey = pass.key;
  await decryptAll();
  updateLockBtn();
  render();
  return true;
}
function lock() { vaultKey = null; plain.clear(); updateLockBtn(); render(); }
async function decryptAll() {
  if (!vaultKey) return;
  plain.clear();
  for (const it of items) if (it.secret && !it.deleted && it.enc) { try { plain.set(it.id, await unseal(vaultKey, it.enc)); } catch {} }
}
function updateLockBtn() {
  const b = $('#btnLock');
  b.hidden = !hasVault() && !items.some((i) => i.secret && !i.deleted);
  setIcon(b, vaultKey ? 'unlock' : 'lock');
  b.title = vaultKey ? '鍵付きクリップを閉じる' : '鍵付きクリップを開く';
  b.classList.toggle('secret-on', !!vaultKey);
  $('#sVault').textContent = hasVault() ? '合言葉を変更' : '合言葉を設定';
}

/* ---------- model ---------- */
const view = (it) => (it.secret ? plain.get(it.id) || null : it);
function persist() { save(LS.items, items); scheduleSync(); }
async function upsert(it, v) {
  const now = Date.now();
  const base = { id: it.id, createdAt: it.createdAt || now, updatedAt: Math.max(now, (it.updatedAt || 0) + 1), pinned: !!it.pinned, archived: !!it.archived };
  let next;
  if (it.secret) {
    if (!vaultKey) throw new Error('locked');
    next = { ...base, secret: true, enc: await seal(vaultKey, v) };
    plain.set(it.id, v);
  } else {
    next = { ...base, ...v };
    plain.delete(it.id);
  }
  const i = items.findIndex((x) => x.id === it.id);
  if (i >= 0) items[i] = next; else items.push(next);
  persist();
  return next;
}
function remove(id) {
  const i = items.findIndex((x) => x.id === id);
  if (i < 0) return;
  items[i] = { id, deleted: true, updatedAt: Math.max(Date.now(), (items[i].updatedAt || 0) + 1) };
  plain.delete(id);
  persist();
}
async function addClip(v, secret = false) {
  if (secret && !(await unlock())) return null;
  const it = { id: uid(), createdAt: Date.now(), secret };
  const r = await upsert(it, v);
  render();
  return r;
}

/* ---------- markdown ---------- */
function itemTitle(v) { return v.title || (v.kind === 'link' ? host(v.url) : (v.text || '').split('\n')[0].slice(0, 40)); }
function itemMd(v) {
  const tags = v.tags?.length ? ' ' + v.tags.map((t) => '#' + t).join(' ') : '';
  if (v.kind === 'link') return `- [${(v.title || v.url).replace(/[[\]]/g, '')}](${v.url})${tags}` + (v.text ? '\n' + v.text.replace(/^/gm, '  ') : '');
  if (v.kind === 'word') return `- ${[v.title, v.text].filter(Boolean).join(' ')}${tags}`;
  return (v.title ? `**${v.title}**\n` : '') + v.text + tags;
}
function listMd(list) { return list.map(({ v }) => itemMd(v)).join('\n\n'); }
function fileMd() {
  const live = items.filter((i) => !i.deleted && !i.secret).sort(sorter);
  const block = (it) => {
    const head = [KIND[it.kind] || 'メモ', isoDate(it.createdAt), ...(it.tags || []).map((t) => '#' + t)].join(' · ');
    return [`### ${itemTitle(it)}`, head, it.url ? `<${it.url}>` : '', it.text || ''].filter(Boolean).join('\n');
  };
  const act = live.filter((i) => !i.archived), arc = live.filter((i) => i.archived);
  return `# Clip\n\n${act.map(block).join('\n\n')}\n\n## アーカイブ\n\n${arc.map(block).join('\n\n')}\n`;
}
function canonicalJson() {
  const sorted = [...items].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return JSON.stringify({ v: 1, meta, items: sorted });
}

/* ---------- render ---------- */
const sorter = (a, b) => (!!b.pinned - !!a.pinned) || (b.createdAt || 0) - (a.createdAt || 0);
function visible() {
  const q = ui.q.trim().toLowerCase();
  return items.filter((it) => !it.deleted && !!it.archived === ui.archive).sort(sorter).map((it) => ({ it, v: view(it) })).filter(({ it, v }) => {
    if (ui.kind === 'secret') { if (!it.secret) return false; }
    else if (ui.kind && (!v || v.kind !== ui.kind)) return false;
    if (ui.tag && (!v || !(v.tags || []).includes(ui.tag))) return false;
    if (q) { if (!v) return false; const hay = [v.title, v.text, v.url, ...(v.tags || [])].join(' ').toLowerCase(); if (!q.split(/\s+/).every((w) => hay.includes(w))) return false; }
    return true;
  });
}
function renderTags() {
  const cnt = new Map();
  for (const it of items) { if (it.deleted || !!it.archived !== ui.archive) continue; const v = view(it); for (const t of v?.tags || []) cnt.set(t, (cnt.get(t) || 0) + 1); }
  if (ui.tag && !cnt.has(ui.tag)) ui.tag = '';
  const box = $('#tags'); box.textContent = '';
  [...cnt.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'ja')).forEach(([t]) => {
    const b = document.createElement('button'); b.className = 'tag' + (ui.tag === t ? ' on' : ''); b.textContent = '#' + t;
    b.onclick = () => { ui.tag = ui.tag === t ? '' : t; render(); };
    box.append(b);
  });
}
function render() {
  renderTags();
  const list = visible();
  $('#count').textContent = list.length;
  const frag = document.createDocumentFragment();
  for (const { it, v } of list) frag.append(row(it, v));
  const box = $('#list'); box.textContent = '';
  if (!list.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = items.some((i) => !i.deleted) ? '該当なし' : 'クリップはまだありません'; box.append(e); }
  box.append(frag);
}
function row(it, v) {
  const el = document.createElement('div'); el.className = 'item' + (it.secret ? ' secret' : '');
  const k = document.createElement('span'); k.className = 'k';
  k.append(svg(!v ? 'lock' : v.kind === 'link' ? 'link' : v.kind === 'word' ? 'word' : 'note'));
  const b = document.createElement('div'); b.className = 'b';
  const m = document.createElement('div'); m.className = 'm';
  if (!v) {
    const t = document.createElement('div'); t.className = 't'; t.textContent = '鍵付きクリップ'; b.append(t);
  } else {
    if (v.title) { const t = document.createElement('div'); t.className = 't'; t.textContent = v.title; b.append(t); }
    const body = v.text || (!v.title ? v.url : '');
    if (body) { const x = document.createElement('div'); x.className = 'x'; x.textContent = body; b.append(x); }
    if (v.url) { const h = document.createElement('span'); h.className = 'h'; h.textContent = host(v.url); m.append(h); }
    for (const t of v.tags || []) { const s = document.createElement('span'); s.className = 'tg'; s.textContent = '#' + t; m.append(s); }
  }
  const d = document.createElement('span'); d.textContent = fmtDate(it.createdAt); m.prepend(d);
  b.append(m);
  el.append(k, b);
  if (it.pinned) { const p = document.createElement('span'); p.className = 'pin'; p.append(svg('pin')); el.append(p); }
  const a = document.createElement('div'); a.className = 'a';
  if (v?.url) { const o = document.createElement('a'); o.className = 'ib sm'; o.title = '開く'; o.href = v.url; o.target = '_blank'; o.rel = 'noopener noreferrer'; o.append(svg('ext')); o.onclick = (e) => e.stopPropagation(); a.append(o); }
  if (v) { const c = document.createElement('button'); c.className = 'ib sm'; c.title = 'コピー'; c.append(svg('copy')); c.onclick = (e) => { e.stopPropagation(); copyText(v.url && !v.text ? v.url : [v.title, v.text, v.url].filter(Boolean).join('\n')); }; a.append(c); }
  el.append(a);
  el.onclick = async () => { if (!v && !(await unlock())) return; openEdit(it.id); };
  return el;
}

/* ---------- edit dialog ---------- */
let editing = null;
function openEdit(id) {
  const it = items.find((x) => x.id === id); const v = view(it); if (!v) return;
  editing = { id, secret: !!it.secret, pinned: !!it.pinned, archived: !!it.archived };
  $('#eTitle').value = v.title || ''; $('#eUrl').value = v.url || ''; $('#eText').value = v.text || '';
  $('#eTags').value = (v.tags || []).map((t) => '#' + t).join(' ');
  $('#dlgEdit').returnValue = '';
  syncEditBtns();
  $('#dlgEdit').showModal();
}
function syncEditBtns() {
  const u = $('#eUrl').value.trim(); const o = $('#eOpen');
  if (/^https?:\/\//.test(u)) { o.href = u; o.hidden = false; } else { o.removeAttribute('href'); o.hidden = true; }
  $('#ePin').setAttribute('aria-pressed', editing.pinned); $('#eArc').setAttribute('aria-pressed', editing.archived);
  setIcon($('#eSec'), editing.secret ? 'lock' : 'unlock'); $('#eSec').classList.toggle('secret-on', editing.secret);
  $('#eSec').title = editing.secret ? '鍵を外す' : '鍵をかける';
  $('#eArc').title = editing.archived ? 'アーカイブから戻す' : 'アーカイブ';
  $('#eKind').textContent = ''; $('#eKind').append(svg(kindOf(editVals()) === 'link' ? 'link' : kindOf(editVals()) === 'word' ? 'word' : 'note'));
}
function editVals() {
  const { tags } = parseTags($('#eTags').value.replace(/(^|\s)(?!#)(\S+)/g, '$1#$2'));
  const v = { title: $('#eTitle').value.trim(), url: $('#eUrl').value.trim(), text: $('#eText').value.replace(/\s+$/, ''), tags };
  v.kind = kindOf(v); return v;
}
$('#eUrl').oninput = syncEditBtns; $('#eTitle').oninput = syncEditBtns; $('#eText').oninput = syncEditBtns;
$('#ePin').onclick = () => { editing.pinned = !editing.pinned; syncEditBtns(); };
$('#eArc').onclick = () => { editing.archived = !editing.archived; syncEditBtns(); };
$('#eSec').onclick = async () => { if (!editing.secret && !(await unlock())) return; editing.secret = !editing.secret; syncEditBtns(); };
$('#eCopy').onclick = () => copyText(itemMd(editVals()));
$('#eDel').onclick = () => { if (!confirm('削除しますか？')) return; remove(editing.id); $('#dlgEdit').close(); render(); };
$('#dlgEdit').addEventListener('close', async () => {
  if ($('#dlgEdit').returnValue !== 'save' || !editing) { editing = null; return; }
  const it = items.find((x) => x.id === editing.id);
  await upsert({ ...it, secret: editing.secret, pinned: editing.pinned, archived: editing.archived }, editVals());
  editing = null; $('#dlgEdit').returnValue = '';
  updateLockBtn(); render();
});

/* ---------- pass dialog ---------- */
function askPass({ title, confirm: twice = false, verify = null, message = '' }) {
  return new Promise((resolve) => {
    const d = $('#dlgPass'), f = $('#fPass'), a = $('#pIn'), b = $('#pIn2'), msg = $('#pMsg');
    $('#pTitle').textContent = title; a.value = b.value = ''; b.hidden = !twice; msg.textContent = message; msg.className = 'msg';
    a.autocomplete = twice ? 'new-password' : 'current-password';
    const done = (v) => { f.onsubmit = null; d.onclose = null; if (d.open) d.close(); resolve(v); };
    f.onsubmit = async (e) => {
      e.preventDefault();
      if (e.submitter && e.submitter.value === 'cancel') return done(null);
      const p = a.value;
      if (p.length < 6) { msg.textContent = '6文字以上にしてください'; msg.className = 'msg err'; return; }
      if (twice && p !== b.value) { msg.textContent = '一致しません'; msg.className = 'msg err'; return; }
      if (verify) { msg.textContent = '確認中…'; msg.className = 'msg'; try { const key = await verify(p); return done({ pass: p, key }); } catch { msg.textContent = '合言葉が違います'; msg.className = 'msg err'; return; } }
      done(p);
    };
    d.onclose = () => done(null);
    d.showModal(); a.focus();
  });
}

/* ---------- composer ---------- */
const cin = $('#cin');
const grow = () => { cin.style.height = 'auto'; cin.style.height = Math.min(cin.scrollHeight + 2, innerHeight * 0.4) + 'px'; };
cin.addEventListener('input', grow);
cin.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); $('#composer').requestSubmit(); } });
$('#composer').onsubmit = async (e) => {
  e.preventDefault();
  const raw = cin.value.trim(); if (!raw) return;
  const r = await addClip(parseInput(raw), ui.secretNew);
  if (r) { cin.value = ''; grow(); if (ui.secretNew) { ui.secretNew = false; syncSecretNew(); } updateLockBtn(); }
};
function syncSecretNew() { const b = $('#btnSecretNew'); b.setAttribute('aria-pressed', ui.secretNew); setIcon(b, ui.secretNew ? 'lock' : 'unlock'); b.classList.toggle('secret-on', ui.secretNew); }
$('#btnSecretNew').onclick = () => { ui.secretNew = !ui.secretNew; syncSecretNew(); };

/* ---------- filters / toolbar ---------- */
$('#kinds').onclick = async (e) => {
  const b = e.target.closest('button'); if (!b) return;
  if (b.dataset.k === 'secret' && !vaultKey && hasVault()) await unlock();
  ui.kind = b.dataset.k; document.querySelectorAll('#kinds button').forEach((x) => x.classList.toggle('on', x === b)); render();
};
$('#btnArchive').onclick = () => { ui.archive = !ui.archive; $('#btnArchive').setAttribute('aria-pressed', ui.archive); render(); };
let qT; $('#q').oninput = (e) => { clearTimeout(qT); qT = setTimeout(() => { ui.q = e.target.value; render(); }, 120); };
$('#btnCopyAll').onclick = () => { const l = visible().filter((x) => x.v); if (!l.length) return toast('コピーする項目がありません'); copyText(listMd(l)); };
$('#btnLock').onclick = () => (vaultKey ? lock() : unlock());
$('#btnSync').onclick = () => (connected() ? sync() : openSettings());

/* ---------- auto lock ---------- */
const LOCK_OPTS = [1, 5, 15, 60, 0];
let lockMin = load(LS.lock, 5); let hiddenAt = 0;
function lockLabel() { $('#sAutoLock').textContent = '自動ロック: ' + (lockMin ? (lockMin >= 60 ? lockMin / 60 + '時間' : lockMin + '分') : 'しない'); }
$('#sAutoLock').onclick = () => { lockMin = LOCK_OPTS[(LOCK_OPTS.indexOf(lockMin) + 1) % LOCK_OPTS.length]; save(LS.lock, lockMin); lockLabel(); };
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hiddenAt = Date.now(); return; }
  if (vaultKey && lockMin && hiddenAt && Date.now() - hiddenAt > lockMin * 60000) lock();
  sync();
});

/* ---------- Dropbox ---------- */
const appKey = () => DEFAULT_APP_KEY || localStorage.getItem(LS.key) || '';
const redirectUri = () => location.origin + location.pathname;
const connected = () => !!load(LS.tok, null)?.r && !!appKey();
async function sha256(s) { return crypto.subtle.digest('SHA-256', enc.encode(s)); }
async function connect() {
  const key = appKey(); if (!key) { $('#sStatus').textContent = 'App keyを入力してください'; $('#sStatus').className = 'msg err'; return; }
  const verifier = rand(48), state = rand(16);
  save(LS.pkce, { verifier, state });
  const p = new URLSearchParams({ client_id: key, response_type: 'code', code_challenge: b64url(await sha256(verifier)), code_challenge_method: 'S256', token_access_type: 'offline', redirect_uri: redirectUri(), state });
  location.href = 'https://www.dropbox.com/oauth2/authorize?' + p;
}
async function finishAuth(code, state) {
  const pk = load(LS.pkce, null); localStorage.removeItem(LS.pkce);
  if (!pk || pk.state !== state) throw new Error('認証の状態が一致しません');
  const r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams({ code, grant_type: 'authorization_code', code_verifier: pk.verifier, client_id: appKey(), redirect_uri: redirectUri() }) });
  if (!r.ok) throw new Error('Dropboxの認証に失敗しました');
  const j = await r.json();
  save(LS.tok, { a: j.access_token, r: j.refresh_token, exp: Date.now() + j.expires_in * 1000 });
}
async function token() {
  const t = load(LS.tok, null); if (!t) throw new Error('未接続');
  if (t.a && t.exp - 60000 > Date.now()) return t.a;
  const r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.r, client_id: appKey() }) });
  if (r.status === 400 || r.status === 401) { localStorage.removeItem(LS.tok); throw new Error('Dropboxに再接続してください'); }
  if (!r.ok) throw new Error('Dropbox: ' + r.status);
  const j = await r.json(); t.a = j.access_token; t.exp = Date.now() + j.expires_in * 1000; save(LS.tok, t); return t.a;
}
async function dbxDownload(path) {
  const r = await fetch('https://content.dropboxapi.com/2/files/download', { method: 'POST', headers: { Authorization: 'Bearer ' + (await token()), 'Dropbox-API-Arg': JSON.stringify({ path }) } });
  if (r.status === 409) { const e = await r.text(); if (e.includes('not_found')) return null; throw new Error('Dropbox: ' + e.slice(0, 80)); }
  if (!r.ok) throw new Error('Dropbox: ' + r.status);
  let rev = null; try { rev = JSON.parse(r.headers.get('Dropbox-API-Result')).rev; } catch {}
  return { text: await r.text(), rev };
}
async function dbxUpload(path, body, rev) {
  const mode = rev ? { '.tag': 'update', update: rev } : (rev === null ? 'overwrite' : 'add');
  const r = await fetch('https://content.dropboxapi.com/2/files/upload', { method: 'POST', headers: { Authorization: 'Bearer ' + (await token()), 'Content-Type': 'application/octet-stream', 'Dropbox-API-Arg': JSON.stringify({ path, mode, mute: true, autorename: false, strict_conflict: !!rev }) }, body: enc.encode(body) });
  if (r.status === 409) { const e = new Error('conflict'); e.conflict = true; throw e; }
  if (!r.ok) throw new Error('Dropbox: ' + r.status);
  return r.json();
}
let syncing = false, syncAgain = false, syncT;
function scheduleSync() { clearTimeout(syncT); syncT = setTimeout(sync, 1200); }
function setSync(state, msg = '') {
  const b = $('#btnSync'); b.classList.remove('spin', 'warn', 'ok');
  if (state === 'off') { setIcon(b, 'cloud-off'); b.title = 'Dropbox未接続'; }
  if (state === 'busy') { setIcon(b, 'sync'); b.classList.add('spin'); b.title = '同期中'; }
  if (state === 'ok') { setIcon(b, 'cloud'); b.classList.add('ok'); b.title = '同期済み ' + fmtDate(load(LS.last, Date.now())); }
  if (state === 'err') { setIcon(b, 'alert'); b.classList.add('warn'); b.title = msg || '同期エラー'; }
  renderSettingsStatus(state, msg);
}
async function sync() {
  if (!connected() || !navigator.onLine) return setSync(connected() ? 'err' : 'off', connected() ? 'オフライン' : '');
  if (syncing) { syncAgain = true; return; }
  syncing = true; setSync('busy');
  try {
    for (let attempt = 0; ; attempt++) {
      const remote = await dbxDownload(DBX_JSON);
      const rd = remote ? JSON.parse(remote.text) : { meta: {}, items: [] };
      if (rd.meta?.salt && rd.meta.salt !== meta.salt) { if (vaultKey) lock(); meta = rd.meta; save(LS.meta, meta); }
      const m = new Map();
      for (const x of [...(rd.items || []), ...items]) { const y = m.get(x.id); if (!y || (x.updatedAt || 0) > (y.updatedAt || 0)) m.set(x.id, x); }
      items = [...m.values()]; save(LS.items, items);
      const out = canonicalJson();
      if (!remote || out !== remote.text) {
        try { await dbxUpload(DBX_JSON, out, remote ? remote.rev || null : undefined); }
        catch (e) { if (e.conflict && attempt < 3) continue; throw e; }
        await dbxUpload(DBX_MD, fileMd(), null);
      }
      break;
    }
    await decryptAll();
    save(LS.last, Date.now());
    render(); updateLockBtn(); setSync('ok');
  } catch (e) { setSync('err', e.message); }
  finally { syncing = false; if (syncAgain) { syncAgain = false; sync(); } }
}
addEventListener('online', sync);
setInterval(() => { if (!document.hidden) sync(); }, 60000);

/* ---------- settings ---------- */
function base() { return location.origin + location.pathname; }
function openSettings() {
  $('#sKey').value = appKey(); $('#sKey').hidden = !!DEFAULT_APP_KEY;
  $('#sConnect').textContent = connected() ? '切断' : '接続';
  const bm = `javascript:(()=>{const s=String(getSelection());window.open('${base()}?url='+encodeURIComponent(location.href)+'&title='+encodeURIComponent(document.title)+(s?'&text='+encodeURIComponent(s):''),'clip','width=420,height=360')})()`;
  $('#sBookmarklet').href = bm;
  $('#sShortcut').value = base() + '?text=';
  lockLabel(); updateLockBtn();
  renderSettingsStatus();
  $('#dlgSettings').showModal();
}
function renderSettingsStatus(state, msg) {
  const s = $('#sStatus'); if (!s) return;
  if (!connected()) { s.textContent = '未接続'; s.className = 'msg'; return; }
  if (state === 'err') { s.textContent = msg; s.className = 'msg err'; return; }
  const l = load(LS.last, 0); s.textContent = '接続済み' + (l ? ' · 最終同期 ' + fmtDate(l) : ''); s.className = 'msg';
}
$('#btnSettings').onclick = openSettings;
$('#sKey').onchange = (e) => localStorage.setItem(LS.key, e.target.value.trim());
$('#sConnect').onclick = () => {
  if (connected()) { if (!confirm('Dropboxとの接続を解除しますか？')) return; localStorage.removeItem(LS.tok); setSync('off'); openSettings(); return; }
  if (!DEFAULT_APP_KEY) localStorage.setItem(LS.key, $('#sKey').value.trim());
  connect();
};
$('#sBookmarklet').onclick = (e) => { e.preventDefault(); toast('ブックマークバーへドラッグしてください'); };
$('#sShortcutCopy').onclick = () => copyText($('#sShortcut').value);
$('#sVault').onclick = async () => {
  if (hasVault()) {
    if (!(await unlock())) return;
    const old = new Map(plain);
    const pass = await askPass({ title: '新しい合言葉', confirm: true }); if (!pass) return;
    const salt = b64(crypto.getRandomValues(new Uint8Array(16))); const key = await deriveKey(pass, salt);
    meta = { salt, check: await seal(key, 'clip') }; save(LS.meta, meta); vaultKey = key;
    for (const it of items) if (it.secret && !it.deleted && old.has(it.id)) await upsert(it, old.get(it.id));
    toast('合言葉を変更しました');
  } else if (await setupVault()) toast('合言葉を設定しました');
  updateLockBtn();
};
$('#sExport').onclick = () => {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([fileMd()], { type: 'text/markdown' }));
  a.download = `clip-${isoDate(Date.now())}.md`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

/* ---------- Google Keep import ---------- */
function loadScript(src) { return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s); }); }
function fromKeep(d) {
  if (!d || typeof d !== 'object' || d.isTrashed || d.createdTimestampUsec == null) return null;
  const links = (d.annotations || []).filter((a) => a.url);
  const url = links[0]?.url || '';
  let text = d.listContent?.length ? d.listContent.map((x) => (x.isChecked ? '- [x] ' : '- [ ] ') + (x.text || '')).join('\n') : (d.textContent || '');
  text = text.replace(/\s+$/, '');
  if (url && text.trim() === url) text = '';
  for (const l of links.slice(1)) if (!text.includes(l.url)) text += (text ? '\n' : '') + l.url;
  const title = (d.title || '').trim() || (url && !text ? (links[0].title || '').trim() : '');
  const tags = (d.labels || []).map((l) => String(l.name || '').trim().replace(/\s+/g, '_')).filter(Boolean);
  const v = { title, text, url, tags }; v.kind = kindOf(v);
  const created = Math.floor(Number(d.createdTimestampUsec) / 1000);
  return { id: 'keep-' + d.createdTimestampUsec, createdAt: created, updatedAt: Math.max(created, Math.floor(Number(d.userEditedTimestampUsec || 0) / 1000)), pinned: !!d.isPinned, archived: !!d.isArchived, v };
}
$('#sImport').onchange = async (e) => {
  const files = [...e.target.files]; e.target.value = '';
  const msg = $('#sImportMsg'); msg.className = 'msg'; msg.textContent = '読み込み中…';
  try {
    const raws = [];
    for (const f of files) {
      if (/\.zip$/i.test(f.name)) {
        if (!window.JSZip) await loadScript('vendor/jszip.min.js');
        const zip = await window.JSZip.loadAsync(f);
        const entries = Object.values(zip.files).filter((z) => !z.dir && /(^|\/)Keep\/[^/]+\.json$/i.test(z.name));
        for (const z of entries) raws.push(await z.async('string'));
      } else raws.push(await f.text());
    }
    const notes = raws.map((s) => { try { return fromKeep(JSON.parse(s)); } catch { return null; } }).filter(Boolean);
    if (!notes.length) { msg.textContent = 'Keepのメモが見つかりませんでした'; msg.className = 'msg err'; return; }
    const sens = notes.filter((n) => SENSITIVE.test([n.v.title, n.v.text].join('\n')));
    if (sens.length && !vaultKey) {
      msg.textContent = `パスワードらしきメモが${sens.length}件あります。鍵をかけて保存するため合言葉が必要です。`;
      if (!(await unlock())) { msg.textContent = '読み込みを中止しました'; return; }
    }
    let added = 0, locked = 0;
    for (const n of notes) {
      const cur = items.find((x) => x.id === n.id);
      if (cur && (cur.deleted || (cur.updatedAt || 0) >= n.updatedAt)) continue;
      const secret = sens.includes(n);
      const it = { id: n.id, createdAt: n.createdAt, updatedAt: n.updatedAt, pinned: n.pinned, archived: n.archived };
      const rec = secret ? { ...it, secret: true, enc: await seal(vaultKey, n.v) } : { ...it, ...n.v };
      if (secret) { plain.set(n.id, n.v); locked++; }
      if (cur) items[items.indexOf(cur)] = rec; else items.push(rec);
      added++;
    }
    persist(); updateLockBtn(); render();
    msg.textContent = `${added}件を読み込みました` + (locked ? `（うち${locked}件は鍵付き）` : '');
  } catch (err) { msg.textContent = '読み込みに失敗しました: ' + err.message; msg.className = 'msg err'; }
};

/* ---------- incoming (share target / bookmarklet / OAuth) ---------- */
async function handleParams() {
  const p = new URLSearchParams(location.search);
  if (![...p.keys()].length) return;
  history.replaceState(null, '', location.pathname);
  if (p.get('code')) {
    try { await finishAuth(p.get('code'), p.get('state')); toast('Dropboxに接続しました'); } catch (e) { toast(e.message); }
    return;
  }
  if (p.get('error')) { toast('Dropboxの接続を中止しました'); return; }
  const url = p.get('url') || '', title = p.get('title') || '', text = p.get('text') || '';
  if (!url && !text && !title) return;
  const v = parseInput(text, { url, title });
  if (!v.url && !v.text && v.title) { v.text = v.title; v.title = ''; v.kind = kindOf(v); }
  await addClip(v);
  toast('保存しました');
  if (window.name === 'clip' && window.opener) setTimeout(() => { sync().finally(() => window.close()); }, 300);
}

/* ---------- boot ---------- */
(async () => {
  updateLockBtn(); syncSecretNew(); render(); grow();
  await handleParams();
  if (connected()) sync(); else setSync('off');
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
