/* Service worker — self-uninstall (kept to clear stale caches from prior versions) */
self.addEventListener("install", (e) => {
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    try {
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
    } catch (_) {}
    try {
      await self.registration.unregister();
    } catch (_) {}
    try {
      const clients = await self.clients.matchAll({ type: "window" });
      for (const client of clients) {
        client.navigate(client.url);
      }
    } catch (_) {}
  })());
});

self.addEventListener("fetch", (e) => {
  // Pass-through; let the network handle everything.
  return;
});
