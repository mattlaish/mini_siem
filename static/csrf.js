(function () {
  'use strict';

  const originalFetch = window.fetch.bind(window);
  const unsafe = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

  window.fetch = function (input, init) {
    const options = Object.assign({}, init || {});
    const method = String(options.method || 'GET').toUpperCase();
    const target = new URL(
      typeof input === 'string' ? input : input.url,
      window.location.href
    );

    if (unsafe.has(method) && target.origin === window.location.origin) {
      const meta = document.querySelector('meta[name="csrf-token"]');
      if (meta && meta.content) {
        const headers = new Headers(options.headers ||
          (typeof input !== 'string' ? input.headers : undefined));
        headers.set('X-CSRF-Token', meta.content);
        options.headers = headers;
      }
    }
    return originalFetch(input, options);
  };
}());
