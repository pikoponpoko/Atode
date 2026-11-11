// Atode — クリップ＆メモ。データは端末内とDropbox（アプリフォルダ）に保存。
import { THEME_KEYS, THEMES } from './themes.js';
const DEFAULT_APP_KEY = '83k9w84j8h7m2t4';
const DBX_JSON = '/atode.json';
const DBX_MD = '/atode.md';
const PBKDF2_ITER = 600000;

const $ = (s) => document.querySelector(s);
const LS = { items: 'atode.items', meta: 'atode.meta', tok: 'atode.dbx', key: 'atode.appkey', rev: 'atode.rev', tagc: 'atode.tagcolors', sort: 'atode.sort', og: 'atode.og', pkce: 'atode.pkce', lock: 'atode.autolock', last: 'atode.lastsync' };
const KIND = { link: 'リンク', word: 'ワード', note: 'メモ' };
const SENSITIVE = /パスワード|password|passwd|credential|api\s*key|secret\s*key|access\s*key|リカバリ(?:ー)?コード|recovery\s*code|\bpass\s*[:：]|\bPW\b|pw\s*[:：]|暗証|パス\s*[:：]|ログイン/i;

const isSensitive = (v) => SENSITIVE.test([v.title, v.text, ...(v.tags || [])].join('\n'));
const load = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };

let items = load(LS.items, []);
let meta = load(LS.meta, {});
let vaultKey = null;
const plain = new Map(); // 鍵付きクリップの復号結果（メモリ内のみ）
const ui = { kind: '', tag: '', q: '', archive: false, secretNew: false, sort: load(LS.sort, 'new') };
const COLORS = [['', 'なし'], ['gray', 'グレー'], ['green', '緑'], ['blue', '青'], ['purple', '紫'], ['red', '赤']];
let tagc = load(LS.tagc, { at: 0, map: {} });
const cardColor = (it, v) => it.color || (v?.tags || []).map((t) => tagc.map[t]).find(Boolean) || '';
function setTagColor(t, c) { if (c) tagc.map[t] = c; else delete tagc.map[t]; tagc.at = Date.now(); save(LS.tagc, tagc); scheduleSync(); render(); }
const sel = new Set();

/* ---------- utils ---------- */
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf) { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s); }
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const URL_RE = /https?:\/\/[^\s<>"'）」』】]+/;
const host = (u) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
const fmtDate = (t) => { const d = new Date(t); const n = new Date(); const p = (x) => String(x).padStart(2, '0'); if (d.toDateString() === n.toDateString()) return p(d.getHours()) + ':' + p(d.getMinutes()); return (d.getFullYear() === n.getFullYear() ? '' : d.getFullYear() + '/') + (d.getMonth() + 1) + '/' + d.getDate(); };
const isoDate = (t) => { const d = new Date(t); const p = (x) => String(x).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; };
function svg(id) { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); const u = document.createElementNS('http://www.w3.org/2000/svg', 'use'); u.setAttribute('href', '#i-' + id); s.append(u); return s; }
function setIcon(btn, id) { btn.querySelector('use').setAttribute('href', '#i-' + id); }
let toastT;
function toast(msg, action, fn, ms) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(toastT);
  if (action) { const b = document.createElement('button'); b.textContent = action; b.onclick = () => { t.hidden = true; fn(); }; t.append(b); }
  toastT = setTimeout(() => (t.hidden = true), ms || (action ? 6000 : 1800));
}
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
  if (it.color) base.color = it.color;
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
const isEmpty = (v) => !!v && !(v.title || '').trim() && !(v.text || '').trim() && !(v.url || '').trim();
function purgeEmpty() {
  let n = 0;
  for (const it of items) if (!it.deleted && !it.secret && isEmpty(it)) { remove(it.id); n++; }
  return n;
}
// パスワードらしき鍵なしメモ（タグ判定を追加する前に読み込んだもの）に鍵をかける
let sensAsked = false;
function checkSensitive() {
  if (sensAsked) return;
  const list = items.filter((it) => !it.deleted && !it.secret && isSensitive(it));
  if (!list.length) return;
  sensAsked = true;
  toast(`パスワードらしきメモ${list.length}件に鍵がかかっていません`, '鍵をかける', () => lockSensitive(), 20000);
}
async function lockSensitive() {
  if (!(await unlock())) { sensAsked = false; return; }
  const list = items.filter((it) => !it.deleted && !it.secret && isSensitive(it));
  for (const it of list) await upsert({ ...it, secret: true }, { title: it.title, text: it.text, url: it.url, tags: it.tags, kind: it.kind });
  updateLockBtn(); render();
  toast(`${list.length}件に鍵をかけました`);
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
  return `# Atode\n\n${act.map(block).join('\n\n')}\n\n## アーカイブ\n\n${arc.map(block).join('\n\n')}\n`;
}
function canonicalJson() {
  const sorted = [...items].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return JSON.stringify({ v: 1, meta, tagColors: tagc, items: sorted });
}

/* ---------- render ---------- */
const sorter = (a, b) => (!!b.pinned - !!a.pinned) || (b.createdAt || 0) - (a.createdAt || 0);
const viewSorter = (a, b) => (!!b.pinned - !!a.pinned) || ((b.createdAt || 0) - (a.createdAt || 0)) * (ui.sort === 'old' ? -1 : 1);
function visible() {
  const q = ui.q.trim().toLowerCase();
  return items.filter((it) => !it.deleted && (!!it.archived === ui.archive || (ui.tag && !ui.archive))).sort(viewSorter).map((it) => ({ it, v: view(it) })).filter(({ it, v }) => {
    if (ui.kind === 'secret') { if (!it.secret) return false; }
    else if (ui.kind && (!v || v.kind !== ui.kind)) return false;
    if (ui.tag && (!v || !(v.tags || []).includes(ui.tag))) return false;
    if (q) { if (!v) return false; const hay = [v.title, v.text, v.url, ...(v.tags || [])].join(' ').toLowerCase(); if (!q.split(/\s+/).every((w) => hay.includes(w))) return false; }
    return true;
  });
}
function renderTags() {
  const cnt = new Map();
  for (const it of items) { if (it.deleted) continue; const v = view(it); for (const t of v?.tags || []) cnt.set(t, (cnt.get(t) || 0) + 1); }
  if (ui.tag && !cnt.has(ui.tag)) ui.tag = '';
  const box = $('#tags'); box.textContent = '';
  [...cnt.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'ja')).forEach(([t]) => {
    const b = document.createElement('button'); b.className = 'tag' + (ui.tag === t ? ' on' : ''); b.textContent = '#' + t;
    if (tagc.map[t]) b.dataset.tc = tagc.map[t];
    b.onclick = () => { ui.tag = ui.tag === t ? '' : t; render(); };
    b.oncontextmenu = (e) => { e.preventDefault(); openColorMenu(e.clientX, e.clientY, tagc.map[t] || '', (c) => setTagColor(t, c)); };
    box.append(b);
  });
}
function render() {
  renderTags();
  const list = visible();
  $('#count').textContent = list.length;
  for (const id of [...sel]) if (!items.some((x) => x.id === id && !x.deleted)) sel.delete(id);
  syncSelBar();
  const box = $('#list'); box.textContent = '';
  if (!list.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = items.some((i) => !i.deleted) ? '該当なし' : 'クリップはまだありません'; box.append(e); return; }
  const arc = ui.archive ? [] : list.filter((x) => x.it.archived); const act = ui.archive ? list : list.filter((x) => !x.it.archived);
  const pinned = act.filter((x) => x.it.pinned), rest = act.filter((x) => !x.it.pinned);
  const section = (label, arr) => {
    if (!arr.length) return;
    if (label) { const h = document.createElement('div'); h.className = 'gh'; h.textContent = label; box.append(h); }
    box.append(masonry(arr.map(({ it, v }) => card(it, v)), box));
  };
  section(pinned.length ? 'ピン留め' : '', pinned);
  section(pinned.length ? 'その他' : '', rest);
  section('アーカイブ', arc);
}
// 左上から横方向に作成日順で並べ、各カードは一番短い列へ置く
function layout() {
  const w = innerWidth;
  if (w <= 520) return { min: 0, gap: 8, n: 2 };
  return w >= 960 ? { min: 248, gap: 12 } : { min: 236, gap: 10 };
}
let colCount = 0;
function masonry(cards, box) {
  const L = layout(); const cs = getComputedStyle(box);
  const W = box.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
  const n = L.n || Math.max(1, Math.floor((W + L.gap) / (L.min + L.gap)));
  colCount = n;
  const g = document.createElement('div'); g.className = 'grid';
  const cols = Array.from({ length: n }, () => { const c = document.createElement('div'); c.className = 'col'; g.append(c); return c; });
  box.append(g);
  cards.forEach((c) => cols[0].append(c));
  const hs = cards.map((c) => c.offsetHeight);
  const sum = new Array(n).fill(0);
  cards.forEach((c, i) => { let k = 0; for (let j = 1; j < n; j++) if (sum[j] < sum[k] - 1) k = j; cols[k].append(c); sum[k] += hs[i] + L.gap; });
  return g;
}
let rzT; addEventListener('resize', () => { clearTimeout(rzT); rzT = setTimeout(() => { const L = layout(); const box = $('#list'); const W = box.clientWidth - 2 * parseFloat(getComputedStyle(box).paddingLeft); const n = L.n || Math.max(1, Math.floor((W + L.gap) / (L.min + L.gap))); if (n !== colCount) render(); }, 120); });

/* ---------- checklist ---------- */
const CB_RE = /^(\s*)[-*]\s\[( |x|X)\]\s?(.*)$/;
const CARD_ROWS = 10;
function bodyEl(it, v) {
  const lines = v.text.split('\n');
  if (!lines.some((l) => CB_RE.test(l))) { const x = document.createElement('p'); x.textContent = v.text; return x; }
  const body = document.createElement('div'); body.className = 'body';
  let buf = [], shown = 0, rest = 0;
  const flush = () => { if (!buf.length) return; const x = document.createElement('p'); x.textContent = buf.join('\n'); body.append(x); shown += Math.min(buf.length, 6); buf = []; };
  lines.forEach((l, i) => {
    if (shown >= CARD_ROWS) { if (l.trim()) rest++; return; }
    const m = l.match(CB_RE); if (!m) { buf.push(l); return; }
    flush();
    if (shown >= CARD_ROWS) { rest++; return; }
    shown++;
    const on = m[2] !== ' ';
    const row = document.createElement('div'); row.className = 'cbr' + (on ? ' on' : ''); row.style.paddingLeft = Math.min(m[1].length, 8) * 6 + 'px';
    const b = document.createElement('button'); b.type = 'button'; b.className = 'cb'; b.setAttribute('role', 'checkbox'); b.setAttribute('aria-checked', on); b.append(svg('check'));
    const t = document.createElement('span'); t.textContent = m[3];
    row.append(b, t);
    b.onclick = (e) => { e.stopPropagation(); if (sel.size) return toggleSel(it.id); toggleCheck(it, i); };
    body.append(row);
  });
  flush();
  if (rest) { const x = document.createElement('div'); x.className = 'more'; x.textContent = '+' + rest; body.append(x); }
  return body;
}
async function toggleCheck(it, i) {
  const v = view(it); if (!v) return;
  const lines = v.text.split('\n'); const m = lines[i].match(CB_RE); if (!m) return;
  lines[i] = lines[i].replace(/\[( |x|X)\]/, m[2] === ' ' ? '[x]' : '[ ]');
  const cur = items.find((x) => x.id === it.id);
  await upsert(cur, { title: v.title, text: lines.join('\n'), url: v.url, tags: v.tags, kind: v.kind });
  render();
}

/* ---------- link preview ---------- */
const og = load(LS.og, {});
const ogQ = []; let ogBusy = false, ogStop = false, ogRT;
const ytId = (u) => { try { const x = new URL(u); if (/(^|\.)youtu\.be$/.test(x.hostname)) return x.pathname.slice(1); if (/(^|\.)youtube\.com$/.test(x.hostname)) return x.searchParams.get('v') || (x.pathname.match(/^\/(shorts|live|embed)\/([^/?]+)/) || [])[2]; } catch {} return null; };
function ogFor(u) { const o = og[u]; if (o && !o.fail) return o; const y = ytId(u); return y ? { i: `https://i.ytimg.com/vi/${y}/mqdefault.jpg` } : null; }
function wantOg(u) { const o = og[u]; if (o && (!o.fail || Date.now() - o.fail < 7 * 864e5)) return; if (!ogQ.includes(u)) ogQ.push(u); pumpOg(); }
async function pumpOg() {
  if (ogBusy || ogStop || !navigator.onLine) return;
  const u = ogQ.shift(); if (!u) return;
  ogBusy = true;
  try {
    const r = await fetch('https://api.microlink.io/?url=' + encodeURIComponent(u));
    if (r.status === 429) { ogStop = true; return; }
    const j = await r.json();
    const d = j.status === 'success' ? j.data || {} : null;
    og[u] = d && (d.title || d.image) ? { t: d.title || '', d: d.description || '', i: d.image?.url || '', ic: d.logo?.url || '' } : { fail: Date.now() };
    save(LS.og, og);
    clearTimeout(ogRT); ogRT = setTimeout(() => { if (!document.querySelector('dialog[open]')) render(); }, 300);
  } catch { og[u] = { fail: Date.now() }; save(LS.og, og); }
  finally { ogBusy = false; setTimeout(pumpOg, 400); }
}
const ogIO = 'IntersectionObserver' in window ? new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { ogIO.unobserve(e.target); wantOg(e.target._url); } }), { rootMargin: '300px' }) : null;
function linkEl(it, v) {
  const a = document.createElement('a'); a.href = v.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.onclick = (e) => { if (sel.size) { e.preventDefault(); return; } e.stopPropagation(); };
  const o = ogFor(v.url);
  const hostTxt = v.title || v.text || o?.t ? host(v.url) : v.url.replace(/^https?:\/\/(www\.)?/, '');
  if (!o) { a.className = 'lk'; a.append(svg('link')); const h = document.createElement('span'); h.textContent = hostTxt; a.append(h); return a; }
  a.className = 'lp';
  if (o.i) { const im = document.createElement('img'); im.src = o.i; im.alt = ''; im.loading = 'lazy'; im.referrerPolicy = 'no-referrer'; im.onerror = () => im.remove(); a.append(im); }
  const tx = document.createElement('div'); tx.className = 'lpt';
  const head = o.t && o.t !== v.title ? o.t : o.d;
  if (head) { const b = document.createElement('b'); b.textContent = head; tx.append(b); }
  const h = document.createElement('span'); h.className = 'lph';
  if (o.ic) { const ic = document.createElement('img'); ic.src = o.ic; ic.alt = ''; ic.referrerPolicy = 'no-referrer'; ic.onerror = () => ic.remove(); h.append(ic); } else h.append(svg('link'));
  const hs = document.createElement('span'); hs.textContent = host(v.url); h.append(hs); tx.append(h);
  a.append(tx);
  return a;
}

/* ---------- color menu ---------- */
let ctxDone = null;
function openColorMenu(x, y, cur, pick) {
  const m = $('#ctx'); m.textContent = '';
  for (const [c, name] of COLORS) {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'sw' + (c === cur ? ' on' : ''); b.dataset.color = c; b.title = name;
    b.onclick = (e) => { e.stopPropagation(); closeCtx(); pick(c); };
    m.append(b);
  }
  m.hidden = false;
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(6, Math.min(x, innerWidth - r.width - 6)) + 'px';
  m.style.top = Math.max(6, Math.min(y, innerHeight - r.height - 6)) + 'px';
  ctxDone = pick;
}
function closeCtx() { $('#ctx').hidden = true; ctxDone = null; }
addEventListener('pointerdown', (e) => { if (!$('#ctx').hidden && !e.target.closest('#ctx')) closeCtx(); }, true);
addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#ctx').hidden) { e.stopPropagation(); closeCtx(); } }, true);
addEventListener('scroll', closeCtx, true); addEventListener('blur', closeCtx);
async function setColor(list, c) {
  for (const it of list) { const v = view(it); if (v) await upsert({ ...it, color: c }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); }
  render();
}

// コピー時は行頭の「・」「•」やチェックボックス記号を外す
const stripBullets = (t) => (t || '').replace(/^([ \t\u3000]*)(?:[・•‧･]|[-*]\s\[[ xX]\])[ \t\u3000]?/gm, '$1');
function iconBtn(icon, title, fn, cls = '') {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'ib sm ' + cls; b.title = title; b.append(svg(icon));
  b.onclick = (e) => { e.stopPropagation(); fn(); }; return b;
}
async function patch(it, fields) { const v = view(it); if (!v) return; await upsert({ ...it, ...fields }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); render(); }
function card(it, v) {
  const el = document.createElement('article'); el.className = 'card' + (it.secret ? ' secret' : '') + (v ? ' ' + v.kind : '');
  const cc = cardColor(it, v); if (cc) el.dataset.color = cc;
  if (!v) {
    const t = document.createElement('div'); t.className = 'locked'; t.append(svg('lock')); t.append('鍵付き'); el.append(t);
  } else {
    if (v.title) { const t = document.createElement('h4'); t.textContent = v.title; el.append(t); }
    if (v.text) el.append(bodyEl(it, v));
    if (v.url) {
      el.append(linkEl(it, v));
      el._url = v.url; el._it = it;
      if (!it.secret && !og[v.url] && ogIO) ogIO.observe(el);
    }
    if (v.tags?.length) { const tg = document.createElement('div'); tg.className = 'tgs'; for (const t of v.tags) { const s = document.createElement('span'); s.textContent = t; tg.append(s); } el.append(tg); }
  }
  const pin = iconBtn('pin', it.pinned ? 'ピン留めを外す' : 'ピン留め', () => patch(it, { pinned: !it.pinned }), 'pinb' + (it.pinned ? ' on' : ''));
  el.append(pin);
  const bar = document.createElement('div'); bar.className = 'acts';
  if (v) bar.append(iconBtn('copy', 'コピー', () => copyText(v.url && !v.text && !v.title ? v.url : [v.title, stripBullets(v.text), v.url].filter(Boolean).join('\n'))));
  bar.append(iconBtn('archive', it.archived ? 'アーカイブから戻す' : 'アーカイブ', () => patch(it, { archived: !it.archived })));
  bar.append(iconBtn('trash', '削除', () => removeWithUndo(it.id), 'danger'));
  if (!v) bar.querySelectorAll('button:not(.danger)').forEach((b) => (b.disabled = true));
  el.append(bar);
  const ck = document.createElement('button'); ck.type = 'button'; ck.className = 'ck'; ck.title = '選択'; ck.append(svg('check'));
  ck.onclick = (e) => { e.stopPropagation(); toggleSel(it.id); };
  el.prepend(ck);
  if (sel.has(it.id)) el.classList.add('sel');
  let lp, lpFired = false;
  el.addEventListener('pointerdown', (e) => { if (e.pointerType !== 'touch') return; lpFired = false; lp = setTimeout(() => { lpFired = true; navigator.vibrate?.(10); toggleSel(it.id); }, 450); });
  ['pointerup', 'pointercancel', 'pointermove'].forEach((t) => el.addEventListener(t, (e) => { if (t !== 'pointermove' || Math.abs(e.movementY) > 3) clearTimeout(lp); }));
  el.addEventListener('contextmenu', (e) => {
    e.preventDefault(); if (lpFired) return;
    const list = sel.has(it.id) ? selItems() : [it];
    openColorMenu(e.clientX, e.clientY, list.length === 1 ? it.color || '' : null, (c) => setColor(list, c));
  });
  el.onclick = async (e) => {
    if (lpFired) { lpFired = false; return; }
    if (sel.size || e.shiftKey || e.ctrlKey || e.metaKey) { toggleSel(it.id); return; }
    if (!v && !(await unlock())) return; openEdit(it.id);
  };
  return el;
}
function toggleSel(id) { sel.has(id) ? sel.delete(id) : sel.add(id); render(); }
function syncSelBar() {
  const on = sel.size > 0;
  document.body.classList.toggle('selecting', on);
  $('#selBar').hidden = !on; $('#selCount').textContent = sel.size + '件を選択';
}
const selItems = () => items.filter((x) => sel.has(x.id) && !x.deleted);
async function bulk(fields) { for (const it of selItems()) { const v = view(it); if (v) await upsert({ ...it, ...fields }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); } sel.clear(); render(); }
$('#selClear').onclick = () => { sel.clear(); render(); };
$('#selPin').onclick = () => bulk({ pinned: !selItems().every((x) => x.pinned) });
$('#selArc').onclick = () => bulk({ archived: !ui.archive });
$('#selColor').onclick = (e) => { const r = e.currentTarget.getBoundingClientRect(); const l = selItems(); openColorMenu(r.left, r.bottom + 4, null, async (c) => { await setColor(l, c); }); };
$('#selCopy').onclick = () => { const l = selItems().map((it) => ({ it, v: view(it) })).filter((x) => x.v); copyText(listMd(l)); };
$('#selDel').onclick = () => {
  const prev = selItems().map((x) => ({ ...x })); const pp = new Map(prev.map((x) => [x.id, plain.get(x.id)]));
  for (const x of prev) remove(x.id); sel.clear(); render();
  toast(prev.length + '件を削除しました', '元に戻す', () => {
    for (const x of prev) { const i = items.findIndex((y) => y.id === x.id); items[i] = { ...x, updatedAt: Date.now() + 1 }; if (pp.get(x.id)) plain.set(x.id, pp.get(x.id)); }
    persist(); render();
  });
};
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && sel.size && !document.querySelector('dialog[open]')) { sel.clear(); render(); } });
document.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== 'a' || e.altKey || e.shiftKey) return;
  if (document.querySelector('dialog[open]') || e.target.closest('input,textarea,select,[contenteditable]')) return;
  e.preventDefault();
  for (const { it } of visible()) sel.add(it.id);
  render();
});
function removeWithUndo(id, msg = '削除しました') {
  const prev = items.find((x) => x.id === id); if (!prev) return;
  const keepPlain = plain.get(id);
  remove(id); render();
  toast(msg, '元に戻す', () => {
    const i = items.findIndex((x) => x.id === id);
    items[i] = { ...prev, updatedAt: Date.now() + 1 };
    if (keepPlain) plain.set(id, keepPlain);
    persist(); render();
  });
}
/* ---------- edit dialog ---------- */
let editing = null;
function openEdit(id) {
  const it = items.find((x) => x.id === id); const v = view(it); if (!v) return;
  editing = { id, secret: !!it.secret, pinned: !!it.pinned, archived: !!it.archived, color: it.color || '' };
  $('#eTitle').value = v.title || ''; $('#eUrl').value = v.url || ''; $('#eText').value = v.text || '';
  setListMode((v.text || '').split('\n').some((l) => CB_RE.test(l)));
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
  if (editing.color) $('#dlgEdit').dataset.color = editing.color; else delete $('#dlgEdit').dataset.color;
  $('#eArc').title = editing.archived ? 'アーカイブから戻す' : 'アーカイブ';
  $('#eKind').textContent = ''; $('#eKind').append(svg(kindOf(editVals()) === 'link' ? 'link' : kindOf(editVals()) === 'word' ? 'word' : 'note'));
}
function editVals() {
  const { tags } = parseTags($('#eTags').value.replace(/(^|\s)(?!#)(\S+)/g, '$1#$2'));
  const v = { title: $('#eTitle').value.trim(), url: $('#eUrl').value.trim(), text: $('#eText').value.replace(/\s+$/, ''), tags };
  v.kind = kindOf(v); return v;
}
/* checklist editor */
const eList = $('#eList');
let listMode = false;
function setListMode(on) {
  listMode = on; $('#eText').hidden = on; eList.hidden = !on;
  $('#eChk').setAttribute('aria-pressed', on);
  if (on) buildList();
}
function buildList() {
  eList.textContent = '';
  const lines = $('#eText').value.replace(/\s+$/, '').split('\n');
  lines.forEach((l) => { const m = l.match(CB_RE); eList.append(m ? erow(m[3], true, m[2] !== ' ', m[1]) : erow(l, false)); });
  const add = document.createElement('button'); add.type = 'button'; add.className = 'eadd'; add.title = '項目を追加'; add.append(svg('plus'));
  add.onclick = () => { const r = erow('', true); add.before(r); focusRow(r, 0); serializeList(); };
  eList.append(add);
  requestAnimationFrame(() => eList.querySelectorAll('textarea').forEach(fit));
}
function fit(t) { t.style.height = 'auto'; t.style.height = t.scrollHeight + 'px'; }
function erow(text, cb, on = false, ind = '') {
  const r = document.createElement('div'); r.className = 'erow' + (cb ? '' : ' plain') + (on ? ' on' : ''); r.dataset.ind = ind;
  if (cb) r.style.paddingLeft = Math.min(ind.length, 8) * 6 + 'px';
  if (cb) {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'cb'; b.setAttribute('role', 'checkbox'); b.setAttribute('aria-checked', on); b.append(svg('check'));
    b.onclick = () => { const v = !r.classList.contains('on'); r.classList.toggle('on', v); b.setAttribute('aria-checked', v); serializeList(); };
    r.append(b);
  }
  const t = document.createElement('textarea'); t.rows = 1; t.value = text; t.enterKeyHint = 'next';
  t.oninput = () => {
    if (t.value.includes('\n')) { const [first, ...more] = t.value.split('\n'); t.value = first; let at = r; more.forEach((x) => { const n = erow(x, cb, false, r.dataset.ind); at.after(n); at = n; }); focusRow(at, at.querySelector('textarea').value.length); eList.querySelectorAll('textarea').forEach(fit); }
    fit(t); serializeList();
  };
  t.onkeydown = (e) => {
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const a = t.selectionStart, tail = t.value.slice(t.selectionEnd); t.value = t.value.slice(0, a); fit(t);
      const n = erow(tail, cb, false, r.dataset.ind); r.after(n); focusRow(n, 0); serializeList();
    } else if (e.key === 'Backspace' && t.selectionStart === 0 && t.selectionEnd === 0) {
      const prev = r.previousElementSibling; if (!prev) return;
      e.preventDefault();
      const pt = prev.querySelector('textarea'), at = pt.value.length; pt.value += t.value; fit(pt); r.remove(); focusRow(prev, at); serializeList();
    }
  };
  r.append(t);
  return r;
}
function focusRow(r, at) { const t = r.querySelector('textarea'); t.focus(); t.setSelectionRange(at, at); }
function serializeList() {
  $('#eText').value = [...eList.querySelectorAll('.erow')].map((r) => {
    const t = r.querySelector('textarea').value;
    return r.classList.contains('plain') ? t : `${r.dataset.ind}- [${r.classList.contains('on') ? 'x' : ' '}] ${t}`;
  }).join('\n');
  syncEditBtns();
}
$('#eChk').onclick = () => {
  const ta = $('#eText');
  if (listMode) { ta.value = ta.value.split('\n').map((l) => { const m = l.match(CB_RE); return m ? m[1] + m[3] : l; }).join('\n'); setListMode(false); ta.focus(); return; }
  const lines = ta.value.replace(/\s+$/, '').split('\n');
  ta.value = lines.map((l) => (CB_RE.test(l) ? l : l.trim() || lines.length === 1 ? '- [ ] ' + l.trim() : l)).join('\n');
  setListMode(true);
  const rs = eList.querySelectorAll('.erow'); const last = rs[rs.length - 1]; if (last) focusRow(last, last.querySelector('textarea').value.length);
};
$('#eUrl').oninput = syncEditBtns; $('#eTitle').oninput = syncEditBtns; $('#eText').oninput = syncEditBtns;
$('#ePin').onclick = () => { editing.pinned = !editing.pinned; syncEditBtns(); };
$('#eArc').onclick = () => { editing.archived = !editing.archived; syncEditBtns(); };
$('#eSec').onclick = async () => { if (!editing.secret && !(await unlock())) return; editing.secret = !editing.secret; syncEditBtns(); };
$('#eColor').onclick = (e) => { const r = e.currentTarget.getBoundingClientRect(); openColorMenu(r.left, r.top - 44, editing.color, (c) => { editing.color = c; syncEditBtns(); }); };
$('#eCopy').onclick = () => copyText(itemMd(editVals()));
$('#eDel').onclick = () => { if (!confirm('削除しますか？')) return; remove(editing.id); $('#dlgEdit').close(); render(); };
$('#dlgEdit').addEventListener('close', async () => {
  if ($('#dlgEdit').returnValue !== 'save' || !editing) { editing = null; return; }
  const it = items.find((x) => x.id === editing.id);
  const vals = editVals();
  if (isEmpty(vals)) { editing = null; $('#dlgEdit').returnValue = ''; removeWithUndo(it.id, '空のカードを削除しました'); return; }
  await upsert({ ...it, secret: editing.secret, pinned: editing.pinned, archived: editing.archived, color: editing.color }, vals);
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
function syncSort() { const b = $('#btnSort'); setIcon(b, ui.sort === 'old' ? 'sort-old' : 'sort-new'); b.title = ui.sort === 'old' ? '古い順' : '新しい順'; }
$('#btnSort').onclick = () => { ui.sort = ui.sort === 'old' ? 'new' : 'old'; save(LS.sort, ui.sort); syncSort(); render(); };
$('#btnArchive').onclick = () => { ui.archive = !ui.archive; $('#btnArchive').setAttribute('aria-pressed', ui.archive); render(); };
let qT; $('#q').oninput = (e) => { clearTimeout(qT); qT = setTimeout(() => { ui.q = e.target.value; render(); }, 120); };
$('#btnCopyAll').onclick = () => { const l = visible().filter((x) => x.v); if (!l.length) return toast('コピーする項目がありません'); copyText(listMd(l)); };
$('#btnLock').onclick = () => (vaultKey ? lock() : unlock());
$('#btnSync').onclick = () => (connected() ? sync() : openSettings());

/* ---------- display ---------- */
const FONTS = [['', '標準（システム）'], ['Noto Sans JP'], ['BIZ UDPGothic'], ['M PLUS 1p'], ['Zen Kaku Gothic New'], ['M PLUS Rounded 1c'], ['Zen Maru Gothic'], ['Kosugi Maru'], ['Noto Serif JP'], ['Shippori Mincho'], ['Zen Old Mincho']];
const SIZES = [['小', 1], ['標準', 1.1], ['大', 1.22], ['特大', 1.36]];
const disp = { font: '', size: 1.1, ...load('atode.display', {}) };
function applyDisplay() {
  const r = document.documentElement.style;
  r.setProperty('--fz', disp.size);
  let l = document.getElementById('gfont');
  if (disp.font) {
    const href = 'https://fonts.googleapis.com/css2?family=' + encodeURIComponent(disp.font).replace(/%20/g, '+') + ':wght@400;500;700&display=swap';
    if (!l) { l = document.createElement('link'); l.id = 'gfont'; l.rel = 'stylesheet'; document.head.append(l); }
    if (l.href !== href) l.href = href;
    r.setProperty('--ff', `"${disp.font}","Hiragino Sans","Noto Sans JP",system-ui,sans-serif`);
  } else { l?.remove(); r.removeProperty('--ff'); }
}
function renderDisplay() {
  const f = $('#sFont'); f.textContent = '';
  for (const [v, label] of FONTS) { const o = document.createElement('option'); o.value = v; o.textContent = label || v; f.append(o); }
  f.value = disp.font;
  const z = $('#sSize'); z.textContent = '';
  for (const [label, v] of SIZES) { const b = document.createElement('button'); b.type = 'button'; b.textContent = label; b.className = disp.size === v ? 'on' : ''; b.onclick = () => { disp.size = v; save('atode.display', disp); applyDisplay(); renderDisplay(); render(); }; z.append(b); }
}
$('#sFont').onchange = (e) => { disp.font = e.target.value; save('atode.display', disp); applyDisplay(); document.fonts?.ready.then(render); };
applyDisplay();

/* ---------- theme ---------- */
const THEME_LIST = [{ id: 'default', n: 'デフォルト', sw: ['#FFFFFF', '#F3F4F7', '#0E1116', '#3355FF', '#7C4DFF', '#E5484D', '#1F9D55'], dk: 0 }, ...THEMES];
const TONES = [['auto', '自動'], ['light', 'ライト'], ['dark', 'ダーク']];
const thm = { id: 'default', tone: 'auto', ...load('atode.theme', {}) };
if (!THEME_LIST.some((t) => t.id === thm.id)) thm.id = 'default';
const darkMq = matchMedia('(prefers-color-scheme: dark)');
const effTone = () => (thm.tone === 'auto' ? (darkMq.matches ? 'dark' : 'light') : thm.tone);
function applyTheme() {
  const r = document.documentElement, t = THEMES.find((x) => x.id === thm.id), tn = effTone();
  THEME_KEYS.forEach((k) => r.style.removeProperty(k));
  r.setAttribute('data-theme', tn);
  if (t) THEME_KEYS.forEach((k, i) => r.style.setProperty(k, t[tn[0]][i]));
  r.style.colorScheme = tn;
  const bg = getComputedStyle(r).getPropertyValue('--bg').trim();
  document.querySelectorAll('meta[name=theme-color]').forEach((m) => m.setAttribute('content', bg));
}
darkMq.addEventListener?.('change', () => { if (thm.tone === 'auto') applyTheme(); });
function setTheme(id, tone) { thm.id = id; if (tone) thm.tone = tone; save('atode.theme', thm); applyTheme(); syncTheme(); }
function buildTheme() {
  const seg = $('#sTone'); seg.textContent = '';
  for (const [v, label] of TONES) { const b = document.createElement('button'); b.type = 'button'; b.dataset.v = v; b.textContent = label; b.onclick = () => setTheme(thm.id, v); seg.append(b); }
  const g = $('#sTheme'); g.textContent = '';
  for (const t of THEME_LIST) {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'tbtn' + (t.dk ? ' dk' : ''); b.dataset.v = t.id; b.title = t.n;
    const sw = document.createElement('span'); sw.className = 'sw';
    for (const c of t.sw) { const i = document.createElement('i'); i.style.background = c; sw.append(i); }
    const tn = document.createElement('span'); tn.className = 'tn'; tn.textContent = t.n; tn.dataset.full = t.n;
    b.append(sw, tn);
    b.onclick = () => { const dt = t.def || 'light'; setTheme(t.id, dt === 'light' && thm.tone === 'auto' ? null : dt); };
    g.append(b);
  }
  const bs = [...g.children], rem = bs.length % 3;
  if (rem === 1) bs[bs.length - 1].style.gridColumn = 'span 3';
  else if (rem === 2) bs[bs.length - 1].style.gridColumn = 'span 2';
}
function fitThemeNames() {
  const m = document.createElement('canvas').getContext('2d'), ff = getComputedStyle(document.body).fontFamily;
  m.font = '700 100px ' + ff;
  document.querySelectorAll('#sTheme .tbtn').forEach((b) => {
    const tn = b.querySelector('.tn'), avail = b.clientWidth - 22; if (avail < 20) return;
    const full = tn.dataset.full; tn.textContent = full; tn.style.whiteSpace = 'nowrap';
    const fs1 = (100 * avail) / m.measureText(full).width;
    if (fs1 >= 8.6) { tn.style.fontSize = Math.min(11, fs1).toFixed(1) + 'px'; return; }
    const ch = Array.from(full), half = Math.ceil(ch.length / 2), l1 = ch.slice(0, half).join(''), l2 = ch.slice(half).join('');
    tn.textContent = ''; tn.append(l1, document.createElement('br'), l2);
    const w2 = Math.max(m.measureText(l1).width, m.measureText(l2).width);
    tn.style.fontSize = Math.min(11, (100 * avail) / w2).toFixed(1) + 'px';
  });
}
function syncTheme() {
  document.querySelectorAll('#sTone button').forEach((b) => b.classList.toggle('on', b.dataset.v === thm.tone));
  document.querySelectorAll('#sTheme .tbtn').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === thm.id)));
}
function renderTheme() { if (!$('#sTheme').children.length) buildTheme(); syncTheme(); requestAnimationFrame(fitThemeNames); }
applyTheme();

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
const redirectUri = () => (location.hostname.endsWith('github.io') ? location.origin + '/Atode/' : location.origin + location.pathname);
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
// Claude などが Dropbox に置いた一括変更ファイル（タグの追加・タグの色）を一度だけ取り込む
const DBX_PATCH = '/atode-patch.json';
async function applyPatch() {
  let f; try { f = await dbxDownload(DBX_PATCH); } catch { return; }
  if (!f) return;
  try {
    const p = JSON.parse(f.text); const now = Date.now(); let n = 0;
    for (const [id, add] of Object.entries(p.addTags || {})) {
      const i = items.findIndex((x) => x.id === id); const it = items[i];
      if (!it || it.deleted || it.secret) continue;
      const tags = [...(it.tags || [])]; for (const t of add) if (!tags.includes(t)) tags.push(t);
      if (tags.length === (it.tags || []).length) continue;
      items[i] = { ...it, tags, updatedAt: Math.max(now, (it.updatedAt || 0) + 1) }; n++;
    }
    if (p.tagColors) { tagc = { at: now, map: { ...tagc.map, ...p.tagColors } }; save(LS.tagc, tagc); }
    if (n) toast(n + '件にタグを付けました');
  } catch {}
  try { await fetch('https://api.dropboxapi.com/2/files/delete_v2', { method: 'POST', headers: { Authorization: 'Bearer ' + (await token()), 'Content-Type': 'application/json' }, body: JSON.stringify({ path: DBX_PATCH }) }); } catch {}
}
// iPhoneのショートカットなどが Dropbox に追記した受信箱（1行1件、URLエンコード可）を取り込んで消す
const DBX_INBOX = '/atode-inbox.txt';
const INBOX_PATH = '/アプリ/Atode' + DBX_INBOX;
async function applyInbox() {
  let f; try { f = await dbxDownload(DBX_INBOX); } catch { return; }
  if (!f) return;
  const lines = f.text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const now = Date.now(); let n = 0;
  lines.forEach((line, i) => {
    let raw = line; try { raw = decodeURIComponent(line); } catch {}
    const id = 'in-' + now.toString(36) + '-' + i;
    const v = parseInput(raw.trim());
    if (isEmpty(v)) return;
    const t = now - (lines.length - i);
    items.push({ id, createdAt: t, updatedAt: t, ...v }); n++;
  });
  try {
    const r = await fetch('https://api.dropboxapi.com/2/files/delete_v2', { method: 'POST', headers: { Authorization: 'Bearer ' + (await token()), 'Content-Type': 'application/json' }, body: JSON.stringify({ path: DBX_INBOX, parent_rev: f.rev || undefined }) });
    if (!r.ok) { items.splice(items.length - n, n); return; }
  } catch { items.splice(items.length - n, n); return; }
  if (n) toast(n + '件を受け取りました');
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
      items = [...m.values()];
      if (rd.tagColors && (rd.tagColors.at || 0) > (tagc.at || 0)) { tagc = rd.tagColors; save(LS.tagc, tagc); }
      if (attempt === 0) { await applyPatch(); await applyInbox(); }
      save(LS.items, items);
      const out = canonicalJson();
      if (!remote || out !== remote.text) {
        try { await dbxUpload(DBX_JSON, out, remote ? remote.rev || null : undefined); }
        catch (e) { if (e.conflict && attempt < 3) continue; throw e; }
        await dbxUpload(DBX_MD, fileMd(), null);
      }
      break;
    }
    await decryptAll();
    if (purgeEmpty()) save(LS.items, items);
    checkSensitive();
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
  const bm = `javascript:(()=>{const s=String(getSelection());window.open('${base()}?url='+encodeURIComponent(location.href)+'&title='+encodeURIComponent(document.title)+(s?'&text='+encodeURIComponent(s):''),'atode','width=420,height=360')})()`;
  $('#sBookmarklet').href = bm;
  $('#sShortcut').value = INBOX_PATH;
  $('#sInstall').parentElement.hidden = !installEvt;
  lockLabel(); updateLockBtn(); renderDisplay(); renderTheme();
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
document.addEventListener('keydown', (e) => { if (e.key !== 'F1') return; e.preventDefault(); const d = $('#dlgSettings'); if (d.open) d.close(); else if (!document.querySelector('dialog[open]')) openSettings(); });
$('#sKey').onchange = (e) => localStorage.setItem(LS.key, e.target.value.trim());
$('#sConnect').onclick = () => {
  if (connected()) { if (!confirm('Dropboxとの接続を解除しますか？')) return; localStorage.removeItem(LS.tok); setSync('off'); openSettings(); return; }
  if (!DEFAULT_APP_KEY) localStorage.setItem(LS.key, $('#sKey').value.trim());
  connect();
};
$('#sBookmarklet').onclick = (e) => { e.preventDefault(); toast('ブックマークバーへドラッグしてください'); };
let installEvt = null;
addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installEvt = e; $('#sInstall').parentElement.hidden = false; });
addEventListener('appinstalled', () => { installEvt = null; $('#sInstall').parentElement.hidden = true; });
$('#sInstall').onclick = async () => { if (!installEvt) return; installEvt.prompt(); await installEvt.userChoice; installEvt = null; $('#sInstall').parentElement.hidden = true; };
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
  a.download = `atode-${isoDate(Date.now())}.md`; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
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
  if (isEmpty(v)) return null;
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
    const sens = notes.filter((n) => isSensitive(n.v));
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
  if (p.get('src') === 'ext') { await Promise.all([sync(), new Promise((r) => setTimeout(r, 700))]); location.hash = 'saved'; return; }
  if (window.name === 'atode' && window.opener) setTimeout(() => { sync().finally(() => window.close()); }, 300);
}

/* ---------- boot ---------- */
(async () => {
  purgeEmpty(); updateLockBtn(); syncSecretNew(); syncSort(); render(); grow();
  if (disp.font) document.fonts?.ready.then(render);
  setTimeout(checkSensitive, 600);
  await handleParams();
  if (connected()) sync(); else setSync('off');
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
