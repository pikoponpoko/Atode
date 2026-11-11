const APP = 'https://pikoponpoko.github.io/atode/';

async function save({ url = '', title = '', text = '' }) {
  if (!/^https?:/.test(url)) url = '';
  const q = new URLSearchParams({ src: 'ext' });
  if (url) q.set('url', url);
  if (title) q.set('title', title);
  if (text) q.set('text', text);
  const cur = await chrome.windows.getCurrent();
  const w = 380, h = 240;
  await chrome.windows.create({
    url: APP + '?' + q, type: 'popup', width: w, height: h, focused: true,
    left: Math.max(0, (cur.left || 0) + (cur.width || w) - w - 16), top: (cur.top || 0) + 72,
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'page', title: 'このページをAtodeに保存', contexts: ['page'] });
    chrome.contextMenus.create({ id: 'sel', title: '選択テキストをAtodeに保存', contexts: ['selection'] });
    chrome.contextMenus.create({ id: 'link', title: 'リンクをAtodeに保存', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'img', title: '画像のURLをAtodeに保存', contexts: ['image'] });
  });
});

chrome.action.onClicked.addListener((tab) => save({ url: tab.url, title: tab.title }));

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'sel') return save({ url: info.pageUrl, title: tab?.title, text: info.selectionText });
  if (info.menuItemId === 'link') return save({ url: info.linkUrl, text: info.selectionText || '' });
  if (info.menuItemId === 'img') return save({ url: info.srcUrl, title: tab?.title });
  return save({ url: info.pageUrl || tab?.url, title: tab?.title });
});

// アプリが保存と同期を終えたら（URLが #saved になったら）小窓を閉じる
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.url && change.url.startsWith(APP) && change.url.endsWith('#saved')) {
    chrome.action.setBadgeBackgroundColor({ color: '#2f6bff' });
    chrome.action.setBadgeText({ text: '✓' });
    setTimeout(() => chrome.action.setBadgeText({ text: '' }), 1500);
    chrome.windows.remove(tab.windowId).catch(() => {});
  }
});
