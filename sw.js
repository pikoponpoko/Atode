const V = 'atode-v28';
const EXT = 'atode-ext';
const IMG = 'atode-img';
const IMG_MAX = 300;
const ASSETS = ['./', 'index.html', 'style.css', 'app.js', 'themes.js', 'manifest.webmanifest', 'icon.svg', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png', 'vendor/jszip.min.js'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(V).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== V && k !== EXT && k !== IMG).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });

// 回線が細いときに待たされないよう、一定時間で諦めてキャッシュを返す
function timeout(p, ms) { return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout')), ms); p.then((r) => { clearTimeout(t); res(r); }, (e) => { clearTimeout(t); rej(e); }); }); }

// アプリ本体: ネットワーク優先、失敗・遅延時はキャッシュ
async function appAsset(req, key) {
  const net = fetch(req).then((r) => { if (r.ok) { const c = r.clone(); caches.open(V).then((ca) => ca.put(key, c)); } return r; });
  const hit = await caches.match(key, { ignoreSearch: true });
  if (!hit) return net;
  try { return await timeout(net, 3000); } catch { return hit; }
}
// Webフォント: 一度読めば以後はキャッシュ
async function cacheFirst(req, name) {
  const hit = await caches.match(req);
  if (hit) return hit;
  const r = await fetch(req);
  if (r.ok || r.type === 'opaque') { const c = r.clone(); caches.open(name).then((ca) => ca.put(req, c)); }
  return r;
}
// サムネイル: キャッシュ優先、件数を超えたら古いものから消す
async function image(req) {
  const ca = await caches.open(IMG);
  const hit = await ca.match(req);
  if (hit) return hit;
  const r = await fetch(req);
  if (r.ok || r.type === 'opaque') {
    await ca.put(req, r.clone()).catch(() => {});
    ca.keys().then((ks) => { for (let i = 0; i < ks.length - IMG_MAX; i++) ca.delete(ks[i]); });
  }
  return r;
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);
  if (u.origin === location.origin) {
    const key = u.pathname.endsWith('/') ? new Request(u.origin + u.pathname) : req;
    e.respondWith(appAsset(req, key).catch(() => caches.match(key, { ignoreSearch: true })).then((r) => r || (req.mode === 'navigate' ? caches.match('index.html') : Response.error())));
    return;
  }
  if (u.hostname === 'fonts.googleapis.com' || u.hostname === 'fonts.gstatic.com') { e.respondWith(cacheFirst(req, EXT)); return; }
  if (req.destination === 'image' && u.protocol === 'https:') e.respondWith(image(req));
});
