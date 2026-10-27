(function () {
  var enabled = false;

  function platform() {
    var ua = navigator.userAgent || '';
    if (/Android/i.test(ua)) return 'Android';
    if (/iPhone|iPad|iPod/i.test(ua)) return null;
    if (/Windows/i.test(ua)) return 'Windows';
    if (/Macintosh/i.test(ua)) return navigator.maxTouchPoints > 1 ? null : 'macOS';
    if (/Linux|X11/i.test(ua)) return 'Linux';
    return null;
  }

  function arm() {
    if (!enabled) return;
    var name = platform();
    if (!name) return;
    document.querySelectorAll('.cerf-download .tabbed-labels > label').forEach(function (label) {
      if (label.textContent.trim().indexOf(name) === 0) label.click();
    });
    var platformButton = document.querySelector('[data-platform="' + name + '"]');
    if (!platformButton) return;
    document.querySelectorAll('.cerf-download-generic').forEach(function (button) {
      button.classList.add('cerf-hidden');
    });
    platformButton.classList.remove('cerf-hidden');
    document.querySelectorAll('.cerf-download-other').forEach(function (button) {
      button.classList.remove('cerf-hidden');
    });
  }

  if (typeof document$ !== 'undefined') {
    document$.subscribe(arm);
  } else {
    document.addEventListener('DOMContentLoaded', arm);
  }
})();
