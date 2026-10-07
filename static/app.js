/* mini-SIEM shell behaviors: mobile nav drawer + light/dark theme toggle.
   Kept external (not inline) so the pages can run under a strict CSP. */
(function () {
  'use strict';

  // ---- theme ----------------------------------------------------------
  var root = document.documentElement;
  function stored() { try { return localStorage.getItem('mini-siem-theme'); } catch (e) { return null; } }
  function apply(mode) {
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
  }
  function current() {
    var attr = root.getAttribute('data-theme');
    if (attr) return attr;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  apply(stored());

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeToggle');
    if (btn) {
      var label = function () {
        var d = current() === 'dark';
        btn.textContent = d ? '☀ Light' : '☾ Dark';
        btn.setAttribute('aria-label', d ? 'Switch to light theme' : 'Switch to dark theme');
      };
      label();
      btn.addEventListener('click', function () {
        var next = current() === 'dark' ? 'light' : 'dark';
        apply(next);
        try { localStorage.setItem('mini-siem-theme', next); } catch (e) {}
        label();
      });
    }

    // ---- mobile nav drawer -------------------------------------------
    var app = document.getElementById('app');
    var ham = document.getElementById('hamburger');
    var scrim = document.getElementById('navScrim');
    function setOpen(open) {
      if (!app) return;
      app.classList.toggle('nav-open', open);
      if (ham) ham.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    if (ham) ham.addEventListener('click', function () { setOpen(!app.classList.contains('nav-open')); });
    if (scrim) scrim.addEventListener('click', function () { setOpen(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') setOpen(false); });
    // Close the drawer after following a nav link on mobile.
    var nav = document.getElementById('primaryNav');
    if (nav) nav.addEventListener('click', function (e) { if (e.target.closest('a')) setOpen(false); });
  });
}());
