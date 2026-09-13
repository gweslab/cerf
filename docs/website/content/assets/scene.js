/* The fixed logo scene on the home page, mirroring yaroslavkibysh.com: the
   background blurs and dims as the page scrolls (src/js/pageAnimations.js), the
   logo zooms in with scroll progress (src/js/graphics.js scales its meshes the
   same way), and it drifts a little with the pointer. */
(function () {
  var MAX_BLUR = 5;      /* px, at the bottom of the page */
  var BASE_DIM = 0.2;    /* overlay opacity at the top - the logo must not fight the text */
  var MAX_DIM  = 0.45;   /* overlay opacity at the bottom */
  var ZOOM     = 0.5;    /* the logo grows by this fraction across the scroll */
  var DRIFT    = 18;     /* px the logo travels across the viewport */

  var scene, overlay, imgs;
  var progress = 0, driftX = 0, driftY = 0;

  function apply() {
    var t = 'translate3d(' + driftX.toFixed(1) + 'px,' + driftY.toFixed(1) + 'px, 0) ' +
            'scale(' + (1 + progress * ZOOM).toFixed(3) + ')';
    for (var n = 0; n < imgs.length; n++) imgs[n].style.transform = t;
  }

  function onScroll() {
    var max = document.documentElement.scrollHeight - window.innerHeight;
    progress = max > 0 ? Math.min(window.scrollY / max, 1) : 0;

    scene.style.filter = 'blur(' + (progress * MAX_BLUR).toFixed(2) + 'px)';
    overlay.style.opacity = BASE_DIM + progress * (MAX_DIM - BASE_DIM);
    apply();
  }

  function onPointer(event) {
    driftX = (event.clientX / window.innerWidth - 0.5) * 2 * DRIFT;
    driftY = (event.clientY / window.innerHeight - 0.5) * 2 * DRIFT;
    apply();
  }

  function arm() {
    scene   = document.querySelector('.cerf-scene');
    overlay = document.querySelector('.cerf-scene-overlay');
    imgs    = scene ? scene.querySelectorAll('img') : [];
    if (!scene || !overlay || !imgs.length) return;   /* not the home page */

    progress = 0;
    driftX = driftY = 0;

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (matchMedia('(hover: hover)').matches) {
      window.addEventListener('mousemove', onPointer, { passive: true });
    }
  }

  if (typeof document$ !== 'undefined') {
    document$.subscribe(arm);
  } else {
    document.addEventListener('DOMContentLoaded', arm);
  }
})();
