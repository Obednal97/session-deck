// Session Deck service worker: shows pushes and opens the chat a notification is about.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json() } catch (x) {}
  if (navigator.setAppBadge && d.n != null) (d.n ? navigator.setAppBadge(d.n) : navigator.clearAppBadge()).catch(() => {});
  e.waitUntil(self.registration.showNotification(d.title || 'Session Deck', { body: d.body || '', tag: d.pane || 'deck', data: { pane: d.pane || '' }, icon: 'icons/192.png' }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close(); const p = e.notification.data && e.notification.data.pane;
  e.waitUntil((async () => {
    const c = (await self.clients.matchAll({ type: 'window', includeUncontrolled: true })).find(c => c.url.startsWith(self.registration.scope) && c.frameType != 'nested');  // not a split-view column
    if (c) { if (p) c.postMessage({ pane: p }); return c.focus() }
    return self.clients.openWindow(self.registration.scope + (p ? '?pane=' + encodeURIComponent(p) : ''));
  })());
});
