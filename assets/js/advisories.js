(function () {
  var q = document.getElementById('adv-q');
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.adv-tab'));
  var rows = Array.prototype.slice.call(document.querySelectorAll('.adv-row'));
  var empties = Array.prototype.slice.call(document.querySelectorAll('.adv-empty'));
  var noResult = document.querySelector('.adv-noresult');
  var echo = document.querySelector('.adv-q-echo');
  if (!q || !tabs.length) { return; }

  var activeTab = 'all';

  function setActive(tab) {
    activeTab = tab;
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-tab') === tab;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }

  function render() {
    var query = q.value.trim().toLowerCase();
    var searching = query.length > 0;
    if (searching) { setActive('all'); } // search spans all ecosystems

    var shown = 0;
    rows.forEach(function (r) {
      var ecoOk = activeTab === 'all' || r.getAttribute('data-eco') === activeTab;
      var textOk = !searching || r.getAttribute('data-search').indexOf(query) !== -1;
      var show = ecoOk && textOk;
      r.hidden = !show;
      if (show) { shown++; }
    });

    empties.forEach(function (e) {
      var ecoOk = activeTab === 'all' || e.getAttribute('data-eco') === activeTab;
      e.hidden = searching || !ecoOk;
    });

    if (noResult) {
      var none = searching && shown === 0;
      noResult.hidden = !none;
      if (none && echo) { echo.textContent = q.value.trim(); }
    }
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      q.value = '';
      setActive(t.getAttribute('data-tab'));
      render();
    });
  });
  q.addEventListener('input', render);
  render();
})();
