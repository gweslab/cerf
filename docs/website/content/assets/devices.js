(function () {
  function arm() {
    var filters = document.querySelector('.cerf-db-filters');
    if (!filters) return;
    var search = filters.querySelector('.cerf-db-search');
    var toggles = filters.querySelectorAll('input[type="checkbox"]');
    var cards = document.querySelectorAll('.cerf-db-card');
    var fields = new Map();
    cards.forEach(function (card) {
      fields.set(card, JSON.parse(card.dataset.search).map(function (field) {
        return field.toLowerCase();
      }));
    });

    function hiddenLevels() {
      var hidden = {};
      toggles.forEach(function (toggle) {
        if (!toggle.checked) hidden[toggle.dataset.support] = true;
      });
      return hidden;
    }

    function matches(card, needle) {
      if (!needle) return true;
      return fields.get(card).some(function (field) {
        return field.indexOf(needle) !== -1;
      });
    }

    function apply() {
      var hidden = hiddenLevels();
      var needle = search.value.trim().toLowerCase();
      cards.forEach(function (card) {
        card.hidden = hidden[card.dataset.support] === true || !matches(card, needle);
      });
    }

    search.addEventListener('input', apply);
    toggles.forEach(function (toggle) {
      toggle.addEventListener('change', apply);
    });
    filters.hidden = false;
    apply();
  }

  if (typeof document$ !== 'undefined') {
    document$.subscribe(arm);
  } else {
    document.addEventListener('DOMContentLoaded', arm);
  }
})();
