// Atode — クリップ＆メモ。データは端末内とDropbox（アプリフォルダ）に保存。
import { THEME_KEYS, THEMES } from './themes.js';
const DEFAULT_APP_KEY = '83k9w84j8h7m2t4';
const DBX_JSON = '/atode.json';
const DBX_MD = '/atode.md';
const PBKDF2_ITER = 600000;

const $ = (s) => document.querySelector(s);
const LS = { autoArc: 'atode.autoarc', items: 'atode.items', meta: 'atode.meta', tok: 'atode.dbx', key: 'atode.appkey', rev: 'atode.rev', tagc: 'atode.tagcolors', sort: 'atode.sort', og: 'atode.og', pkce: 'atode.pkce', lock: 'atode.autolock', last: 'atode.lastsync' };
const KIND = { link: 'リンク', word: 'ワード', note: 'メモ' };
const SENSITIVE = /パスワード|password|passwd|credential|api\s*key|secret\s*key|access\s*key|リカバリ(?:ー)?コード|recovery\s*code|\bpass\s*[:：]|\bPW\b|pw\s*[:：]|暗証|パス\s*[:：]|ログイン/i;

const isSensitive = (v) => SENSITIVE.test([v.title, v.text, ...(v.tags || [])].join('\n'));
const load = (k, d) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };

let items = load(LS.items, []);
let meta = load(LS.meta, {});
let vaultKey = null;
const plain = new Map(); // 鍵付きクリップの復号結果（メモリ内のみ）
const ui = { kind: '', tag: '', q: '', view: '', unread: false, secretNew: false, sort: load(LS.sort, 'new'), rows: load('atode.rows', false) };
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
  if (it.trashed) base.trashed = it.trashed;
  if (it.readAt) base.readAt = it.readAt;
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
const alive = (it) => !it.deleted && !it.trashed;
const TRASH_DAYS = 30;
// 削除はゴミ箱へ（内容を残す）。hard のときだけ中身を消した墓標にする
function remove(id, hard = false) {
  const i = items.findIndex((x) => x.id === id);
  if (i < 0) return;
  const updatedAt = Math.max(Date.now(), (items[i].updatedAt || 0) + 1);
  if (hard) { items[i] = { id, deleted: true, updatedAt }; plain.delete(id); }
  else items[i] = { ...items[i], trashed: Date.now(), updatedAt };
  persist();
}
function restore(id) {
  const i = items.findIndex((x) => x.id === id);
  if (i < 0 || !items[i].trashed) return;
  const { trashed, ...rest } = items[i];
  items[i] = { ...rest, updatedAt: Math.max(Date.now(), (rest.updatedAt || 0) + 1) };
  persist();
}
function purgeTrash() {
  const lim = Date.now() - TRASH_DAYS * 864e5; let n = 0;
  for (const it of items) if (!it.deleted && it.trashed && it.trashed < lim) { remove(it.id, true); n++; }
  return n;
}
const isEmpty = (v) => !!v && !(v.title || '').trim() && !(v.text || '').trim() && !(v.url || '').trim();
function purgeEmpty() {
  let n = 0;
  for (const it of items) if (!it.deleted && !it.secret && isEmpty(it)) { remove(it.id, true); n++; }
  return n;
}
// パスワードらしき鍵なしメモ（タグ判定を追加する前に読み込んだもの）に鍵をかける
let sensAsked = false;
function checkSensitive() {
  if (sensAsked) return;
  const list = items.filter((it) => alive(it) && !it.secret && isSensitive(it));
  if (!list.length) return;
  sensAsked = true;
  toast(`パスワードらしきメモ${list.length}件に鍵がかかっていません`, '鍵をかける', () => lockSensitive(), 20000);
}
async function lockSensitive() {
  if (!(await unlock())) { sensAsked = false; return; }
  const list = items.filter((it) => alive(it) && !it.secret && isSensitive(it));
  for (const it of list) await upsert({ ...it, secret: true }, { title: it.title, text: it.text, url: it.url, tags: it.tags, kind: it.kind });
  updateLockBtn(); render();
  toast(`${list.length}件に鍵をかけました`);
}
// 同じページかどうかの判定用（ハッシュと計測用パラメータ、末尾の / を無視）
const normUrl = (u) => {
  try {
    const x = new URL(u); x.hash = '';
    for (const k of [...x.searchParams.keys()]) if (/^(utm_|fbclid$|gclid$|igshid$|si$|ref_src$)/.test(k)) x.searchParams.delete(k);
    return x.hostname.replace(/^www\./, '') + x.pathname.replace(/\/+$/, '') + x.search;
  } catch { return (u || '').trim(); }
};
function findDup(url) {
  if (!url) return null; const n = normUrl(url);
  return items.find((it) => !it.deleted && view(it)?.url && normUrl(view(it).url) === n) || null;
}
let lastDup = false;
async function addClip(v, secret = false) {
  lastDup = false;
  const d = !secret && findDup(v.url);
  if (d) {
    // 既存のカードを先頭へ上げ、新しく付いたタグやメモを足す
    const dv = view(d);
    const tags = [...new Set([...(dv.tags || []), ...(v.tags || [])])];
    const text = v.text && !(dv.text || '').includes(v.text) ? [dv.text, v.text].filter(Boolean).join('\n') : dv.text || '';
    const nv = { title: dv.title || v.title || '', text, url: dv.url, tags }; nv.kind = kindOf(nv);
    const { trashed, ...rest } = d;
    const r = await upsert({ ...rest, archived: false, createdAt: Date.now() }, nv);
    lastDup = true; render(); toast('保存済みのクリップを先頭に移動しました');
    return r;
  }
  if (secret && !(await unlock())) return null;
  const it = { id: uid(), createdAt: Date.now(), secret };
  const r = await upsert(it, v);
  render();
  return r;
}

/* ---------- markdown ---------- */
const ogTitle = (u) => (u && og[u] && !og[u].fail ? og[u].t || '' : '');
function itemTitle(v) { return v.title || (v.kind === 'link' ? ogTitle(v.url) || host(v.url) : (v.text || '').split('\n')[0].slice(0, 40)); }
function itemMd(v) {
  const tags = v.tags?.length ? ' ' + v.tags.map((t) => '#' + t).join(' ') : '';
  if (v.kind === 'link') return `- [${(v.title || ogTitle(v.url) || v.url).replace(/[[\]]/g, '')}](${v.url})${tags}` + (v.text ? '\n' + v.text.replace(/^/gm, '  ') : '');
  if (v.kind === 'word') return `- ${[v.title, v.text].filter(Boolean).join(' ')}${tags}`;
  return (v.title ? `**${v.title}**\n` : '') + v.text + tags;
}
function listMd(list) { return list.map(({ v }) => itemMd(v)).join('\n\n'); }
function fileMd() {
  const live = items.filter((i) => alive(i) && !i.secret).sort(sorter);
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
const viewSorter = (a, b) => (ui.view === 'trash' ? (b.trashed || 0) - (a.trashed || 0) : (!!b.pinned - !!a.pinned) || (ui.sort === 'upd' ? (b.updatedAt || 0) - (a.updatedAt || 0) : ((b.createdAt || 0) - (a.createdAt || 0)) * (ui.sort === 'old' ? -1 : 1)));
const inView = (it) => (ui.view === 'trash' ? !it.deleted && !!it.trashed : alive(it) && (!!it.archived === (ui.view === 'archive') || (!!ui.tag && !ui.view)));
function visible() {
  const q = ui.q.trim().toLowerCase();
  return items.filter(inView).sort(viewSorter).map((it) => ({ it, v: view(it) })).filter(({ it, v }) => {
    if (ui.kind === 'secret') { if (!it.secret) return false; }
    else if (ui.kind && (!v || v.kind !== ui.kind)) return false;
    if (ui.unread && (!v || v.kind !== 'link' || it.readAt)) return false;
    if (ui.tag && (!v || !(v.tags || []).includes(ui.tag))) return false;
    if (q) { if (!v) return false; const o = !it.secret && og[v.url]; const hay = [v.title, v.text, v.url, o && !o.fail ? o.t + ' ' + o.d : '', ...(v.tags || [])].join(' ').toLowerCase(); if (!q.split(/\s+/).every((w) => hay.includes(w))) return false; }
    return true;
  });
}
function renderTags() {
  const cnt = new Map();
  for (const it of items) { if (!alive(it)) continue; const v = view(it); for (const t of v?.tags || []) cnt.set(t, (cnt.get(t) || 0) + 1); }
  if (ui.tag && !cnt.has(ui.tag)) ui.tag = '';
  const box = $('#tags'); box.textContent = '';
  [...cnt.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'ja')).forEach(([t]) => {
    const b = document.createElement('button'); b.className = 'tag' + (ui.tag === t ? ' on' : ''); b.textContent = '#' + t;
    if (tagc.map[t]) b.dataset.tc = tagc.map[t];
    b.onclick = () => { ui.tag = ui.tag === t ? '' : t; render(); };
    b.oncontextmenu = (e) => { e.preventDefault(); openTagMenu(e.clientX, e.clientY, t); };
    box.append(b);
  });
}
// 再描画中に一覧が空になってもスクロール位置が先頭に飛ばないよう、高さと位置を保つ
let focusNext = null;
function render() {
  const box = $('#list'), y = scrollY;
  const fid = focusNext || document.activeElement?.closest?.('#list .card')?.dataset.id; focusNext = null;
  box.style.minHeight = box.offsetHeight + 'px';
  try { renderList(); } finally { box.style.minHeight = ''; if (scrollY !== y) scrollTo(0, y); }
  if (fid) box.querySelector(`.card[data-id="${CSS.escape(fid)}"]`)?.focus({ preventScroll: true });
}
function renderList() {
  renderTags();
  const list = visible();
  $('#count').textContent = list.length;
  for (const id of [...sel]) if (!items.some((x) => x.id === id && !x.deleted)) sel.delete(id);
  syncSelBar();
  const box = $('#list'); box.textContent = ''; box.classList.toggle('rowmode', ui.rows);
  if (ui.view === 'trash' && list.length) {
    const h = document.createElement('div'); h.className = 'gh trashh';
    const l = document.createElement('span'); l.textContent = `${TRASH_DAYS}日後に完全に削除されます`;
    const b = document.createElement('button'); b.type = 'button'; b.className = 'btn sm'; b.textContent = 'ゴミ箱を空にする';
    b.onclick = () => { if (!confirm(`ゴミ箱の${list.length}件を完全に削除しますか？`)) return; for (const { it } of list) remove(it.id, true); render(); };
    h.append(l, b); box.append(h);
  }
  if (!list.length) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = ui.view === 'trash' ? 'ゴミ箱は空です' : items.some(alive) ? '該当なし' : 'クリップはまだありません'; box.append(e); return; }
  const flat = ui.view === 'trash';
  const arc = ui.view || flat ? [] : list.filter((x) => x.it.archived); const act = ui.view || flat ? list : list.filter((x) => !x.it.archived);
  const pinned = flat ? [] : act.filter((x) => x.it.pinned), rest = flat ? act : act.filter((x) => !x.it.pinned);
  const section = (label, arr) => {
    if (!arr.length) return;
    if (label) { const h = document.createElement('div'); h.className = 'gh'; h.textContent = label; box.append(h); }
    if (ui.rows) { const r = document.createElement('div'); r.className = 'rows'; for (const { it, v } of arr) r.append(rowCard(it, v)); box.append(r); }
    else box.append(masonry(arr.map(({ it, v }) => card(it, v)), box));
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
let rzT; addEventListener('resize', () => { clearTimeout(rzT); rzT = setTimeout(() => { const L = layout(); const box = $('#list'); const W = box.clientWidth - 2 * parseFloat(getComputedStyle(box).paddingLeft); const n = L.n || Math.max(1, Math.floor((W + L.gap) / (L.min + L.gap))); if (!ui.rows && n !== colCount) render(); }, 120); });

/* ---------- checklist ---------- */
const CB_RE = /^(\s*)[-*]\s\[( |x|X)\]\s?(.*)$/;
/* 本文中のURL。末尾の句読点・閉じ括弧はURLに含めない */
const TXT_URL_RE = /https?:\/\/[^\s<>"'`「」『』（）【】、。，．]+/g;
const trimUrl = (u) => {
  for (;;) {
    const t = u.replace(/[.,;:!?\]}>'"]+$/, '');
    if (t.endsWith(')') && (t.match(/\(/g) || []).length < (t.match(/\)/g) || []).length) { u = t.slice(0, -1); continue; }
    if (t === u) return u; u = t;
  }
};
function urlsIn(t) { return [...new Set([...(t || '').matchAll(TXT_URL_RE)].map((m) => trimUrl(m[0])).filter((u) => u.length > 10))]; }
function linkText(el, text) {
  let at = 0;
  for (const m of (text || '').matchAll(TXT_URL_RE)) {
    const u = trimUrl(m[0]); if (u.length <= 10) continue;
    if (m.index > at) el.append(text.slice(at, m.index));
    const a = document.createElement('a'); a.className = 'il'; a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = u;
    a.onclick = (e) => { if (sel.size) { e.preventDefault(); return; } e.stopPropagation(); };
    el.append(a); at = m.index + u.length;
  }
  if (at < (text || '').length) el.append(text.slice(at));
  return el;
}
/* チェックリストの塊ごとに、チェック済みを末尾へ寄せた並び（元の行番号の配列）を返す */
function checkOrder(lines) {
  const ord = []; let blk = [];
  const flush = () => { ord.push(...blk.filter((k) => !/^\s*[-*]\s\[[xX]\]/.test(lines[k])), ...blk.filter((k) => /^\s*[-*]\s\[[xX]\]/.test(lines[k]))); blk = []; };
  lines.forEach((l, k) => { if (CB_RE.test(l)) blk.push(k); else { flush(); ord.push(k); } });
  flush();
  return ord;
}
const sortChecks = (lines) => checkOrder(lines).map((k) => lines[k]);
function bodyEl(it, v) {
  const lines = sortChecks(v.text.split('\n'));
  if (!lines.some((l) => CB_RE.test(l))) return linkText(document.createElement('p'), v.text);
  const body = document.createElement('div'); body.className = 'body';
  let buf = [];
  const flush = () => { if (!buf.length) return; body.append(linkText(document.createElement('p'), buf.join('\n'))); buf = []; };
  lines.forEach((l, i) => {
    const m = l.match(CB_RE); if (!m) { buf.push(l); return; }
    flush();
    const on = m[2] !== ' ';
    const row = document.createElement('div'); row.className = 'cbr' + (on ? ' on' : ''); row.style.paddingLeft = Math.min(m[1].length, 8) * 6 + 'px';
    const b = document.createElement('button'); b.type = 'button'; b.className = 'cb'; b.setAttribute('role', 'checkbox'); b.setAttribute('aria-checked', on); b.append(svg('check'));
    const t = linkText(document.createElement('span'), m[3]);
    row.append(b, t);
    b.onclick = (e) => { e.stopPropagation(); if (sel.size) return toggleSel(it.id); toggleCheck(it, i); };
    body.append(row);
  });
  flush();
  return body;
}
/* チェックした項目はチェックリストの塊の末尾へ、外した項目は未チェックの末尾へ移す */
function reorderCheck(arr, i, on, isCb, isOn) {
  let a = i, b = i;
  while (a > 0 && isCb(arr[a - 1])) a--;
  while (b < arr.length - 1 && isCb(arr[b + 1])) b++;
  const [x] = arr.splice(i, 1); b--;
  let to = b + 1;
  if (!on) for (let k = a; k <= b; k++) if (isOn(arr[k])) { to = k; break; }
  arr.splice(to, 0, x);
  return to;
}
async function toggleCheck(it, i) {
  const v = view(it); if (!v) return;
  const lines = sortChecks(v.text.split('\n')); const m = lines[i].match(CB_RE); if (!m) return;
  lines[i] = lines[i].replace(/\[( |x|X)\]/, m[2] === ' ' ? '[x]' : '[ ]');
  reorderCheck(lines, i, m[2] === ' ', (l) => CB_RE.test(l), (l) => /^\s*[-*]\s\[[xX]\]/.test(l));
  const cur = items.find((x) => x.id === it.id);
  await upsert(cur, { title: v.title, text: lines.join('\n'), url: v.url, tags: v.tags, kind: v.kind });
  render();
}

/* ---------- link preview ---------- */
const og = load(LS.og, {});
let mdDirty = false;
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
    save(LS.og, og); if (og[u].t) mdDirty = true;
    clearTimeout(ogRT); ogRT = setTimeout(() => { if (!document.querySelector('dialog[open]')) render(); }, 300);
  } catch { og[u] = { fail: Date.now() }; save(LS.og, og); }
  finally { ogBusy = false; setTimeout(pumpOg, 400); }
}
const ogIO = 'IntersectionObserver' in window ? new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { ogIO.unobserve(e.target); wantOg(e.target._url); } }), { rootMargin: '300px' }) : null;
function linkEl(it, v) {
  const a = document.createElement('a'); a.href = v.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.onclick = (e) => { if (sel.size) { e.preventDefault(); return; } e.stopPropagation(); markRead(it); };
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
  if (!v) {
    const t = document.createElement('div'); t.className = 'locked'; t.append(svg('lock')); t.append('鍵付き'); el.append(t);
  } else {
    if (v.title) { const t = document.createElement('h4'); t.textContent = v.title; el.append(t); }
    if (v.text) el.append(bodyEl(it, v));
    if (v.url) el.append(linkEl(it, v));
    if (v.tags?.length) { const tg = document.createElement('div'); tg.className = 'tgs'; for (const t of v.tags) { const s = document.createElement('span'); s.textContent = t; tg.append(s); } el.append(tg); }
  }
  return wire(el, it, v);
}
/* リスト表示の1行 */
function rowCard(it, v) {
  const el = document.createElement('article'); el.className = 'card rc' + (it.secret ? ' secret' : '') + (v ? ' ' + v.kind : '');
  const o = v?.url && !it.secret ? ogFor(v.url) : null;
  let ic;
  if (o?.ic) { ic = document.createElement('img'); ic.src = o.ic; ic.alt = ''; ic.referrerPolicy = 'no-referrer'; ic.onerror = () => ic.replaceWith(svg('link')); }
  else ic = svg(!v ? 'lock' : v.kind === 'link' ? 'link' : v.kind === 'word' ? 'word' : 'note');
  const k = document.createElement('span'); k.className = 'rk'; k.append(ic);
  const t = document.createElement('span'); t.className = 'rt';
  const b = document.createElement('b'); b.textContent = v ? itemTitle(v) : '鍵付き'; t.append(b);
  if (v) {
    const sub = v.url ? (v.title || ogTitle(v.url) ? host(v.url) : v.url.replace(/^https?:\/\/(www\.)?[^/]+/, '').replace(/^\/$/, '')) : v.title ? (v.text || '').split('\n').find((l) => l.trim()) || '' : (v.text || '').split('\n').slice(1).find((l) => l.trim()) || '';
    if (sub) { const s = document.createElement('span'); s.textContent = stripBullets(sub); t.append(s); }
  }
  el.append(k, t);
  if (v?.tags?.length) { const tg = document.createElement('span'); tg.className = 'tgs'; for (const x of v.tags) { const s = document.createElement('span'); s.textContent = x; tg.append(s); } el.append(tg); }
  const d = document.createElement('time'); d.textContent = fmtDate(ui.view === 'trash' ? it.trashed : ui.sort === 'upd' ? it.updatedAt : it.createdAt); el.append(d);
  return wire(el, it, v);
}
function markRead(it) {
  const cur = items.find((x) => x.id === it.id); if (!cur || cur.readAt || cur.trashed) return;
  const auto = load(LS.autoArc, false) && !cur.archived;
  setTimeout(() => {
    patch(cur, auto ? { readAt: Date.now(), archived: true } : { readAt: Date.now() });
    if (auto) toast('アーカイブしました', '元に戻す', () => { const c = items.find((x) => x.id === it.id); if (c) patch(c, { archived: false }); });
  }, 0);
}
function openLink(it, v) { if (!v?.url) return; window.open(v.url, '_blank', 'noopener,noreferrer'); markRead(it); }
function wire(el, it, v) {
  const rows = el.classList.contains('rc');
  el.dataset.id = it.id; el.tabIndex = -1;
  if (it.readAt && v?.kind === 'link') el.classList.add('read');
  const cc = cardColor(it, v); if (cc) el.dataset.color = cc;
  if (v?.url) { el._url = v.url; el._it = it; if (!it.secret && !og[v.url] && ogIO) ogIO.observe(el); }
  const bar = document.createElement('div'); bar.className = 'acts';
  if (it.trashed) {
    bar.append(iconBtn('restore', '元に戻す', () => { restore(it.id); render(); toast('元に戻しました'); }));
    bar.append(iconBtn('trash', '完全に削除', () => { if (confirm('完全に削除しますか？')) { remove(it.id, true); render(); } }, 'danger'));
  } else {
    const pin = iconBtn('pin', it.pinned ? 'ピン留めを外す' : 'ピン留め', () => patch(it, { pinned: !it.pinned }), 'pinb' + (it.pinned ? ' on' : ''));
    if (rows) { if (v?.url) bar.append(iconBtn('ext', '開く', () => openLink(it, v))); bar.append(pin); } else el.append(pin);
    if (v) bar.append(iconBtn('copy', 'コピー', () => copyText(v.url && !v.text && !v.title ? v.url : [v.title, stripBullets(v.text), v.url].filter(Boolean).join('\n'))));
    bar.append(iconBtn('archive', it.archived ? 'アーカイブから戻す' : 'アーカイブ', () => patch(it, { archived: !it.archived })));
    bar.append(iconBtn('trash', '削除', () => removeWithUndo(it.id), 'danger'));
    if (!v) bar.querySelectorAll('button:not(.danger)').forEach((b) => (b.disabled = true));
  }
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
  const tr = ui.view === 'trash';
  setIcon($('#selArc'), tr ? 'restore' : 'archive'); $('#selArc').title = tr ? '元に戻す' : ui.view === 'archive' ? 'アーカイブから戻す' : 'アーカイブ';
  $('#selDel').title = tr ? '完全に削除' : '削除';
  for (const id of ['#selPin', '#selColor', '#selRead']) $(id).hidden = tr;
  if (on && !tr) { const r = selItems().filter((x) => view(x)?.kind === 'link'); const allRead = r.length && r.every((x) => x.readAt); $('#selRead').hidden = !r.length; $('#selRead').title = allRead ? '未読に戻す' : '既読にする'; }
}
const selItems = () => items.filter((x) => sel.has(x.id) && !x.deleted);
async function bulk(fields) { for (const it of selItems()) { const v = view(it); if (v) await upsert({ ...it, ...fields }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); } sel.clear(); render(); }
$('#selClear').onclick = () => { sel.clear(); render(); };
$('#selPin').onclick = () => bulk({ pinned: !selItems().every((x) => x.pinned) });
$('#selArc').onclick = () => { if (ui.view === 'trash') { for (const x of selItems()) restore(x.id); sel.clear(); render(); return; } bulk({ archived: ui.view !== 'archive' }); };
$('#selRead').onclick = () => { const r = selItems().filter((x) => view(x)?.kind === 'link'); const allRead = r.every((x) => x.readAt); sel.clear(); (async () => { for (const x of r) { const v = view(x); await upsert({ ...x, readAt: allRead ? 0 : x.readAt || Date.now() }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); } render(); })(); };
$('#selColor').onclick = (e) => { const r = e.currentTarget.getBoundingClientRect(); const l = selItems(); openColorMenu(r.left, r.bottom + 4, null, async (c) => { await setColor(l, c); }); };
$('#selCopy').onclick = () => { const l = selItems().map((it) => ({ it, v: view(it) })).filter((x) => x.v); copyText(listMd(l)); };
$('#selDel').onclick = () => {
  if (ui.view === 'trash') { const l = selItems(); if (!confirm(`${l.length}件を完全に削除しますか？`)) return; for (const x of l) remove(x.id, true); sel.clear(); render(); return; }
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
  document.activeElement?.blur();
  if (!listMode) fit($('#eText'));
  $('#dlgEdit').scrollTop = 0;
}
function syncEditBtns() {
  const u = $('#eUrl').value.trim(); const o = $('#eOpen');
  if (/^https?:\/\//.test(u)) { o.href = u; o.hidden = false; } else { o.removeAttribute('href'); o.hidden = true; }
  $('#ePin').setAttribute('aria-pressed', editing.pinned); $('#eArc').setAttribute('aria-pressed', editing.archived);
  setIcon($('#eSec'), editing.secret ? 'lock' : 'unlock'); $('#eSec').classList.toggle('secret-on', editing.secret);
  $('#eSec').title = editing.secret ? '鍵を外す' : '鍵をかける';
  const dc = cardColor({ color: editing.color }, editVals()); if (dc) $('#dlgEdit').dataset.color = dc; else delete $('#dlgEdit').dataset.color;
  $('#eArc').title = editing.archived ? 'アーカイブから戻す' : 'アーカイブ';
  $('#eKind').textContent = ''; $('#eKind').append(svg(kindOf(editVals()) === 'link' ? 'link' : kindOf(editVals()) === 'word' ? 'word' : 'note'));
  syncLinks();
}
/* 本文中のURLを編集欄の下に開けるリンクとして並べる（textarea内はリンクにできないため） */
function syncLinks() {
  const box = $('#eLinks'), us = urlsIn($('#eText').value).filter((u) => u !== $('#eUrl').value.trim());
  if (box.dataset.u === us.join('\n')) return;
  box.dataset.u = us.join('\n'); box.textContent = ''; box.hidden = !us.length;
  for (const u of us) {
    const a = document.createElement('a'); a.className = 'lk'; a.href = u; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.title = u; a.append(svg('ext'));
    const h = document.createElement('span'); h.textContent = u.replace(/^https?:\/\/(www\.)?/, ''); a.append(h); box.append(a);
  }
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
  const lines = sortChecks($('#eText').value.replace(/\s+$/, '').split('\n'));
  $('#eText').value = lines.join('\n');
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
    b.onclick = () => {
      const v = !r.classList.contains('on'); r.classList.toggle('on', v); b.setAttribute('aria-checked', v);
      const rows = [...eList.querySelectorAll('.erow')], i = rows.indexOf(r);
      const to = reorderCheck(rows, i, v, (x) => !x.classList.contains('plain'), (x) => x.classList.contains('on'));
      const next = rows[to + 1]; if (next) next.before(r); else if (rows[to - 1]) rows[to - 1].after(r);
      serializeList();
    };
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
  if (listMode) { ta.value = ta.value.split('\n').map((l) => { const m = l.match(CB_RE); return m ? m[1] + m[3] : l; }).join('\n'); setListMode(false); fit(ta); ta.focus(); return; }
  const lines = ta.value.replace(/\s+$/, '').split('\n');
  ta.value = lines.map((l) => (CB_RE.test(l) ? l : l.trim() || lines.length === 1 ? '- [ ] ' + l.trim() : l)).join('\n');
  setListMode(true);
  const rs = eList.querySelectorAll('.erow'); const last = rs[rs.length - 1]; if (last) focusRow(last, last.querySelector('textarea').value.length);
};
$('#eTags').oninput = syncEditBtns; $('#eUrl').oninput = syncEditBtns; $('#eTitle').oninput = syncEditBtns; $('#eText').oninput = () => { fit($('#eText')); syncEditBtns(); };
$('#ePin').onclick = () => { editing.pinned = !editing.pinned; syncEditBtns(); };
$('#eArc').onclick = () => { editing.archived = !editing.archived; syncEditBtns(); };
$('#eSec').onclick = async () => { if (!editing.secret && !(await unlock())) return; editing.secret = !editing.secret; syncEditBtns(); };
$('#eColor').onclick = (e) => { const r = e.currentTarget.getBoundingClientRect(); openColorMenu(r.left, r.top - 44, editing.color, (c) => { editing.color = c; syncEditBtns(); }); };
$('#eCopy').onclick = () => copyText(itemMd(editVals()));
$('#eDel').onclick = () => {
  const id = editing.id, it = items.find((x) => x.id === id);
  if (it?.trashed) { if (!confirm('完全に削除しますか？')) return; editing = null; $('#dlgEdit').close(); remove(id, true); render(); return; }
  editing = null; $('#dlgEdit').close(); removeWithUndo(id);
};
$('#eOpen').addEventListener('click', () => { const it = editing && items.find((x) => x.id === editing.id); const v = it && view(it); if (v && !it.readAt && !it.trashed && $('#eUrl').value.trim() === v.url) upsert({ ...it, readAt: Date.now() }, { title: v.title, text: v.text, url: v.url, tags: v.tags, kind: v.kind }); });
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
const SORTS = [['new', 'sort-new', '新しい順'], ['old', 'sort-old', '古い順'], ['upd', 'sort-upd', '更新順']];
function syncSort() { const [, ic, t] = SORTS.find((x) => x[0] === ui.sort) || SORTS[0]; const b = $('#btnSort'); setIcon(b, ic); b.title = t; }
$('#btnSort').onclick = () => { ui.sort = SORTS[(SORTS.findIndex((x) => x[0] === ui.sort) + 1) % SORTS.length][0]; save(LS.sort, ui.sort); syncSort(); render(); };
function syncFilters() {
  $('#btnArchive').setAttribute('aria-pressed', ui.view === 'archive'); $('#btnTrash').setAttribute('aria-pressed', ui.view === 'trash');
  $('#btnUnread').setAttribute('aria-pressed', ui.unread);
  const b = $('#btnLayout'); setIcon(b, ui.rows ? 'grid' : 'rows'); b.title = ui.rows ? 'カード表示' : 'リスト表示';
}
const setView = (v) => { ui.view = ui.view === v ? '' : v; sel.clear(); syncFilters(); scrollTo(0, 0); render(); };
$('#btnArchive').onclick = () => setView('archive');
$('#btnTrash').onclick = () => setView('trash');
$('#btnUnread').onclick = () => { ui.unread = !ui.unread; syncFilters(); render(); };
$('#btnLayout').onclick = () => { ui.rows = !ui.rows; save('atode.rows', ui.rows); syncFilters(); render(); };
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
      if (!it || !alive(it) || it.secret) continue;
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
    if (isEmpty(v) || findDup(v.url)) return;
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
        await dbxUpload(DBX_MD, fileMd(), null); mdDirty = false;
      } else if (mdDirty) { mdDirty = false; await dbxUpload(DBX_MD, fileMd(), null); }
      break;
    }
    await decryptAll();
    if (purgeEmpty() + purgeTrash()) save(LS.items, items);
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
  lockLabel(); autoArcLabel(); updateLockBtn(); renderDisplay(); renderTheme();
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
      if (cur && (cur.deleted || cur.trashed || (cur.updatedAt || 0) >= n.updatedAt)) continue;
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

/* ---------- tag menu (color / rename / merge / delete) ---------- */
function openTagMenu(x, y, t) {
  openColorMenu(x, y, tagc.map[t] || '', (c) => setTagColor(t, c));
  const m = $('#ctx');
  const row = document.createElement('div'); row.className = 'crow';
  const inp = document.createElement('input'); inp.value = t; inp.title = '名前を変更（既存のタグ名にすると統合）'; inp.spellcheck = false;
  inp.onkeydown = (e) => {
    if (e.isComposing || e.keyCode === 229) return;
    if (e.key === 'Enter') { e.preventDefault(); const n = inp.value.trim().replace(/^#+/, '').replace(/\s+/g, '_'); closeCtx(); if (n && n !== t) renameTag(t, n); }
  };
  const del = document.createElement('button'); del.type = 'button'; del.className = 'ib sm danger'; del.title = 'タグを削除'; del.append(svg('trash'));
  del.onclick = (e) => { e.stopPropagation(); closeCtx(); deleteTag(t); };
  row.append(inp, del); m.append(row);
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(6, Math.min(x, innerWidth - r.width - 6)) + 'px';
  m.style.top = Math.max(6, Math.min(y, innerHeight - r.height - 6)) + 'px';
}
async function mapTags(t, fn) {
  if (hasVault() && !vaultKey && items.some((it) => !it.deleted && it.secret)) await unlock();
  let n = 0;
  for (const it of [...items]) {
    if (it.deleted) continue; const v = view(it); if (!v || !(v.tags || []).includes(t)) continue;
    await upsert(it, { title: v.title, text: v.text, url: v.url, tags: fn(v.tags), kind: v.kind }); n++;
  }
  return n;
}
async function renameTag(t, n) {
  const merge = items.some((it) => !it.deleted && (view(it)?.tags || []).includes(n));
  if (merge && !confirm(`#${t} を #${n} に統合しますか？`)) return;
  const c = await mapTags(t, (tags) => [...new Set(tags.map((x) => (x === t ? n : x)))]);
  if (tagc.map[t] && !tagc.map[n]) tagc.map[n] = tagc.map[t];
  delete tagc.map[t]; tagc.at = Date.now(); save(LS.tagc, tagc); scheduleSync();
  if (ui.tag === t) ui.tag = n;
  render(); toast(`${c}件のタグを変更しました`);
}
async function deleteTag(t) {
  if (!confirm(`#${t} をすべてのクリップから外しますか？`)) return;
  const c = await mapTags(t, (tags) => tags.filter((x) => x !== t));
  delete tagc.map[t]; tagc.at = Date.now(); save(LS.tagc, tagc); scheduleSync();
  if (ui.tag === t) ui.tag = '';
  render(); toast(`${c}件からタグを外しました`);
}

/* ---------- keyboard ---------- */
const editableEl = (t) => t?.closest?.('input,textarea,select,[contenteditable]');
const curCard = () => document.activeElement?.closest?.('#list .card');
function moveFocus(dir) {
  const cards = [...document.querySelectorAll('#list .card')]; if (!cards.length) return;
  const cur = curCard();
  let best = null;
  if (!cur) best = cards.find((c) => c.getBoundingClientRect().bottom > 60) || cards[0];
  else {
    const r0 = cur.getBoundingClientRect(), cx = r0.left + r0.width / 2, cy = r0.top + r0.height / 2; let bd = Infinity;
    for (const c of cards) {
      if (c === cur) continue;
      const r = c.getBoundingClientRect(), dx = r.left + r.width / 2 - cx, dy = r.top + r.height / 2 - cy;
      const main = dir === 'down' ? dy : dir === 'up' ? -dy : dir === 'right' ? dx : -dx, off = dir === 'up' || dir === 'down' ? Math.abs(dx) : Math.abs(dy);
      if (main <= 1) continue;
      const d = main + off * 3; if (d < bd) { bd = d; best = c; }
    }
  }
  if (best) { best.focus({ preventScroll: true }); best.scrollIntoView({ block: 'nearest' }); }
}
// 操作でカードが一覧から消えるとき、隣のカードへフォーカスを移す
function neighborId(el) {
  const cards = [...document.querySelectorAll('#list .card')]; const i = cards.indexOf(el);
  return (cards[i + 1] || cards[i - 1])?.dataset.id || null;
}
const KEYS = { ArrowDown: 'down', ArrowUp: 'up', ArrowLeft: 'left', ArrowRight: 'right', j: 'down', k: 'up', h: 'left', l: 'right' };
document.addEventListener('keydown', (e) => {
  if (e.isComposing || e.ctrlKey || e.metaKey || e.altKey || document.querySelector('dialog[open]') || !$('#ctx').hidden) return;
  if (editableEl(e.target)) { if (e.key === 'Escape' && e.target.matches('#q,#cin')) e.target.blur(); return; }
  const cur = curCard(), it = cur && items.find((x) => x.id === cur.dataset.id), v = it && view(it);
  if (KEYS[e.key]) { e.preventDefault(); moveFocus(KEYS[e.key]); return; }
  switch (e.key) {
    case '/': e.preventDefault(); $('#q').focus(); $('#q').select(); return;
    case 'n': e.preventDefault(); scrollTo(0, 0); cin.focus(); return;
  }
  if (!it) return;
  const gone = (fn) => { focusNext = neighborId(cur); fn(); };
  switch (e.key) {
    case 'Enter': if (e.target === cur) { e.preventDefault(); cur.click(); } return;
    case 'x': e.preventDefault(); toggleSel(it.id); return;
    case 'o': e.preventDefault(); if (v) openLink(it, v); return;
    case 'p': if (!it.trashed && v) { e.preventDefault(); focusNext = it.id; patch(it, { pinned: !it.pinned }); } return;
    case 'u': if (!it.trashed && v?.kind === 'link') { e.preventDefault(); focusNext = it.id; patch(it, { readAt: it.readAt ? 0 : Date.now() }); } return;
    case 'e': if (!it.trashed && v) { e.preventDefault(); gone(() => patch(it, { archived: !it.archived })); } return;
    case 'Delete': case 'Backspace':
      e.preventDefault();
      if (it.trashed) { if (confirm('完全に削除しますか？')) gone(() => { remove(it.id, true); render(); }); }
      else gone(() => removeWithUndo(it.id));
      return;
  }
});

/* ---------- paste / drop to save ---------- */
async function quickSave(raw, extra) {
  const v = parseInput(raw.trim(), extra); if (isEmpty(v)) return;
  const r = await addClip(v); if (r && !lastDup) toast('保存しました');
}
document.addEventListener('paste', (e) => {
  if (document.querySelector('dialog[open]') || editableEl(e.target)) return;
  const s = e.clipboardData?.getData('text/plain'); if (!s?.trim()) return;
  e.preventDefault(); quickSave(s);
});
let dragInside = false, dragDepth = 0;
const dropOk = (e) => !dragInside && !document.querySelector('dialog[open]') && [...(e.dataTransfer?.types || [])].some((t) => t === 'text/uri-list' || t === 'text/plain');
document.addEventListener('dragstart', () => { dragInside = true; });
document.addEventListener('dragend', () => { dragInside = false; });
document.addEventListener('dragenter', (e) => { if (!dropOk(e)) return; dragDepth++; document.body.classList.add('dropping'); });
document.addEventListener('dragleave', () => { if (dragDepth && --dragDepth === 0) document.body.classList.remove('dropping'); });
document.addEventListener('dragover', (e) => { if (dropOk(e) && !e.target.closest?.('#cin')) e.preventDefault(); });
document.addEventListener('drop', (e) => {
  dragDepth = 0; document.body.classList.remove('dropping');
  if (!dropOk(e) || e.target.closest?.('#cin')) return;
  e.preventDefault();
  const dt = e.dataTransfer;
  const url = (dt.getData('text/uri-list') || '').split(/\r?\n/).find((l) => l && !l.startsWith('#')) || '';
  let title = '';
  const html = dt.getData('text/html');
  if (url && html) { const a = new DOMParser().parseFromString(html, 'text/html').querySelector('a'); const t = a?.textContent.trim(); if (t && t !== url) title = t; }
  const text = dt.getData('text/plain') || '';
  if (url) quickSave(text.trim() === url ? '' : text, { url, title }); else quickSave(text);
});

/* ---------- auto archive / Dropbox history ---------- */
function autoArcLabel() { $('#sAutoArc').textContent = '開いたリンクをアーカイブ: ' + (load(LS.autoArc, false) ? 'オン' : 'オフ'); }
$('#sAutoArc').onclick = () => { save(LS.autoArc, !load(LS.autoArc, false)); autoArcLabel(); };
const fmtFull = (t) => { const d = new Date(t), p = (x) => String(x).padStart(2, '0'); return `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`; };
$('#sRevs').onclick = async () => {
  if (!connected()) { toast('Dropboxに接続してください'); return; }
  const box = $('#rList'); box.textContent = ''; $('#rMsg').textContent = '読み込み中…'; $('#rMsg').className = 'msg';
  $('#dlgRevs').showModal();
  try {
    const r = await fetch('https://api.dropboxapi.com/2/files/list_revisions', { method: 'POST', headers: { Authorization: 'Bearer ' + (await token()), 'Content-Type': 'application/json' }, body: JSON.stringify({ path: DBX_JSON, mode: 'path', limit: 100 }) });
    if (!r.ok) throw new Error('Dropbox: ' + r.status);
    const { entries = [] } = await r.json();
    $('#rMsg').textContent = entries.length ? '' : '履歴がありません';
    entries.forEach((x, i) => {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'rrow';
      const d = document.createElement('span'); d.textContent = fmtFull(x.server_modified);
      const z = document.createElement('span'); z.textContent = i === 0 ? '現在' : Math.max(1, Math.round(x.size / 1024)) + ' KB';
      b.append(d, z); b.disabled = i === 0;
      b.onclick = () => restoreRev(x.rev, fmtFull(x.server_modified));
      box.append(b);
    });
  } catch (err) { $('#rMsg').textContent = err.message; $('#rMsg').className = 'msg err'; }
};
async function restoreRev(rev, when) {
  let rd;
  try { const f = await dbxDownload('rev:' + rev); rd = JSON.parse(f.text); } catch (err) { $('#rMsg').textContent = '読み込めませんでした: ' + err.message; $('#rMsg').className = 'msg err'; return; }
  const sameKey = !rd.meta?.salt || rd.meta.salt === meta.salt;
  const olds = (rd.items || []).filter((x) => sameKey || !x.secret);
  const n = olds.filter(alive).length;
  if (!confirm(`${when} の状態（${n}件）に戻しますか？\nこの時点になかったクリップはゴミ箱へ移します。`)) return;
  const old = new Map(olds.map((x) => [x.id, x]));
  const now = Date.now(); let k = 0;
  items = items.map((it) => {
    const o = old.get(it.id); k++;
    if (o) { old.delete(it.id); return { ...o, updatedAt: Math.max(now, it.updatedAt || 0) + k }; }
    if (!alive(it) || (it.secret && !sameKey)) return it;
    return { ...it, trashed: now, updatedAt: Math.max(now, it.updatedAt || 0) + k };
  });
  for (const o of old.values()) items.push({ ...o, updatedAt: now + ++k });
  persist(); await decryptAll(); updateLockBtn(); render();
  $('#dlgRevs').close(); $('#dlgSettings').close();
  toast(`${when} の状態に戻しました`);
}

/* ---------- boot ---------- */
(async () => {
  purgeEmpty(); purgeTrash(); updateLockBtn(); syncSecretNew(); syncSort(); syncFilters(); render(); grow();
  if (disp.font) document.fonts?.ready.then(render);
  setTimeout(checkSensitive, 600);
  await handleParams();
  if (connected()) sync(); else setSync('off');
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
