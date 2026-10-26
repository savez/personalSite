(function () {
  var q = document.getElementById('adv-q');
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.adv-tab'));
  var chips = Array.prototype.slice.call(document.querySelectorAll('.adv-sev-chip'));
  var rows = Array.prototype.slice.call(document.querySelectorAll('.adv-row'));
  var noResult = document.querySelector('.adv-noresult');
  var qWrap = document.querySelector('.adv-q-wrap');
  var echo = document.querySelector('.adv-q-echo');

  // Crawl: duplicate the items so the -50% translate loops seamlessly.
  // The copy is hidden from assistive tech and out of the tab order.
  var track = document.querySelector('.adv-ticker-track');
  if (track) {
    Array.prototype.slice.call(track.children).forEach(function (li) {
      var copy = li.cloneNode(true);
      copy.setAttribute('aria-hidden', 'true');
      Array.prototype.slice.call(copy.querySelectorAll('a')).forEach(function (a) {
        a.setAttribute('tabindex', '-1');
      });
      track.appendChild(copy);
    });
  }

  if (!q || !tabs.length) { return; }

  var activeTab = 'all';
  var activeSevs = {};
  chips.forEach(function (c) { activeSevs[c.getAttribute('data-sev')] = true; });

  function inTab(r, tab) {
    return tab === 'all' || (' ' + r.getAttribute('data-cats') + ' ').indexOf(' ' + tab + ' ') !== -1;
  }

  function render() {
    var query = q.value.trim().toLowerCase();
    var counts = {};
    tabs.forEach(function (t) { counts[t.getAttribute('data-tab')] = 0; });

    var shown = 0;
    rows.forEach(function (r) {
      var match = activeSevs[r.getAttribute('data-sev')] &&
        (!query || r.getAttribute('data-search').indexOf(query) !== -1);
      // Tab counts reflect severity + text, so each tab says how many hits it holds.
      if (match) {
        tabs.forEach(function (t) {
          var tab = t.getAttribute('data-tab');
          if (inTab(r, tab)) { counts[tab]++; }
        });
      }
      var show = match && inTab(r, activeTab);
      r.hidden = !show;
      if (show) { shown++; }
    });

    tabs.forEach(function (t) {
      var n = t.querySelector('.n');
      if (n) { n.textContent = counts[t.getAttribute('data-tab')]; }
    });

    if (noResult) {
      noResult.hidden = shown > 0 || !rows.length;
      if (qWrap) { qWrap.hidden = !query; }
      if (echo) { echo.textContent = q.value.trim(); }
    }
  }

  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      activeTab = t.getAttribute('data-tab');
      tabs.forEach(function (o) {
        var on = o === t;
        o.classList.toggle('active', on);
        o.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
      render();
    });
  });

  chips.forEach(function (c) {
    c.addEventListener('click', function () {
      var sev = c.getAttribute('data-sev');
      activeSevs[sev] = !activeSevs[sev];
      c.setAttribute('aria-pressed', activeSevs[sev] ? 'true' : 'false');
      render();
    });
  });

  q.addEventListener('input', render);
  render();
})();
