(function () {
  var ENTRANCE_MS = 900;

  function show(el, delay) {
    setTimeout(function () {
      el.classList.add('cerf-shown');
      setTimeout(function () { el.classList.add('cerf-done'); }, ENTRANCE_MS);
    }, delay || 0);
  }

  function showOnScroll(el, staggerDelay) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        show(el, staggerDelay);
        observer.unobserve(el);
      });
    }, { threshold: 0.1 });

    observer.observe(el);
  }

  function arm() {
    var hero = document.querySelector('.cerf-hero');
    if (hero) show(hero, 0);

    document.querySelectorAll('.cerf-pill').forEach(function (el, i) {
      show(el, 200 + i * 80);
    });

    var stats = document.querySelector('.cerf-stats');
    if (stats) show(stats, 500);

    document.querySelectorAll('.cerf-hero ~ h2').forEach(function (el) {
      showOnScroll(el, 0);
    });

    document.querySelectorAll('.cerf-wall').forEach(function (wall) {
      wall.querySelectorAll('.cerf-device, .cerf-card').forEach(function (el, i) {
        showOnScroll(el, i * 80);
      });
    });

    document.querySelectorAll('.cerf-rail-track').forEach(function (track) {
      track.querySelectorAll('.cerf-device').forEach(function (el, i) {
        showOnScroll(el, Math.min(i, 6) * 80);
      });
    });

    document.querySelectorAll('.cerf-banner, .cerf-video').forEach(function (el) {
      showOnScroll(el, 0);
    });
  }

  function boot() {
    if (!('IntersectionObserver' in window)) {
      document.documentElement.classList.remove('cerf-anim');
      return;
    }
    arm();
  }

  if (typeof document$ !== 'undefined') {
    document$.subscribe(boot);
  } else {
    document.addEventListener('DOMContentLoaded', boot);
  }
})();
