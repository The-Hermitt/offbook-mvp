const CACHE_NAME = 'offbook-v1';
const ASSETS = [
  '/',
  '/app-tabs.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/js/speech-timing.js',
  '/js/stt-lite.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => (
      Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))
    ))
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  if (request.method !== 'GET') return;
  event.respondWith(
    caches.match(request).then(cached => cached || fetch(request))
  );
});
