/* Kebnetrails audit UI — page logic. Components come from window.Kebnetrails
   (the design system bundle inlined above); this file only fetches, filters
   and mounts. */
(function () {
  'use strict';
  var K = window.Kebnetrails;

  var records = [];
  var byId = new Map();
  var lastSeq = 0;
  var selected = null;
  var follow = true;
  var filters = { q: '', final: '', source: '', llm: '', session: '', tool: '' };
  var chain = { state: 'unknown' };
  var sessions = new Set();
  var tools = new Set();

  var $ = function (id) { return document.getElementById(id); };
  var chrome = $('chrome');
  var statSlot = $('stat');
  var filterSlot = $('filters');
  var main = $('main');
  var rowsEl = $('rows');
  var headEl = $('head');
  var emptyEl = $('empty');
  var detailSlot = $('detail');

  /* ---- chrome ---- */

  function drawStat() {
    var s = { total: records.length, allow: 0, ask: 0, deny: 0, defer: 0 };
    for (var i = 0; i < records.length; i++) {
      var v = K.verdictOf(records[i]);
      if (v in s) s[v]++;
    }
    statSlot.replaceChildren(K.StatBar({
      title: 'Kebnetrails audit trail',
      stats: s,
      chain: chain,
      actions: [
        { label: 'follow', active: follow, onClick: function (b) {
            follow = !follow;
            b.classList.toggle('is-on', follow);
            b.setAttribute('aria-pressed', follow ? 'true' : 'false');
            if (follow) window.scrollTo(0, document.body.scrollHeight);
          } },
        { label: 'verify', onClick: verify }
      ]
    }));
    measureChrome();
  }

  function measureChrome() {
    document.documentElement.style.setProperty('--chrome-h', chrome.offsetHeight + 'px');
  }

  var filterBar = K.FilterBar({
    value: filters,
    sessions: [],
    tools: [],
    onChange: function (v) { filters = v; drawRows(); }
  });
  filterSlot.appendChild(filterBar);

  // Add newly seen sessions and tools without rebuilding the bar, so typing in
  // the search field survives a poll.
  function syncOptions() {
    var selects = filterBar.querySelectorAll('.k-field select');
    [[selects[3], sessions, true], [selects[4], tools, false]].forEach(function (pair) {
      var sel = pair[0], values = pair[1], truncate = pair[2];
      if (!sel) return;
      var have = new Set(Array.prototype.map.call(sel.options, function (o) { return o.value; }));
      Array.from(values).sort().forEach(function (v) {
        if (have.has(v)) return;
        sel.appendChild(new Option(truncate && v.length > 14 ? v.slice(0, 14) + '…' : v, v));
      });
    });
  }

  /* ---- filtering ---- */

  function matches(r) {
    var f = filters;
    if (f.final && K.verdictOf(r) !== f.final) return false;
    if (f.source && (r.final || {}).source !== f.source) return false;
    if (f.llm && String((r.llm || {}).status || '').indexOf(f.llm) !== 0) return false;
    if (f.session && (r.agent || {}).session_id !== f.session) return false;
    if (f.tool && (r.tool || {}).name !== f.tool) return false;
    if (f.q) {
      var hay = [
        (r.tool || {}).input, (r.tool || {}).name, (r.llm || {}).reason, (r.llm || {}).roe_clause,
        (r.final || {}).reason, (r.agent || {}).session_id, (r.agent || {}).agent_type, r.cwd
      ].concat(((r.falco || {}).rules || []).map(function (x) { return x.rule + ' ' + x.message; }))
        .join(' ').toLowerCase();
      if (hay.indexOf(f.q.toLowerCase().trim()) < 0) return false;
    }
    return true;
  }

  /* ---- trail ---- */

  function drawRows() {
    var frag = document.createDocumentFragment();
    var shown = 0;
    for (var i = 0; i < records.length; i++) {
      var r = records[i];
      if (!matches(r)) continue;
      shown++;
      frag.appendChild(K.RecordRow({
        record: r,
        selected: r.seq === selected,
        onSelect: select
      }));
    }
    rowsEl.replaceChildren(frag);
    emptyEl.hidden = shown > 0;
    headEl.hidden = shown === 0;
    if (follow && shown) window.scrollTo(0, document.body.scrollHeight);
  }

  function select(seq) {
    if (seq === selected) return close();
    selected = seq;
    var r = byId.get(seq);
    if (!r) return;
    detailSlot.replaceChildren(K.RecordDetail({ record: r, onClose: close }));
    main.classList.add('is-open');
    rowsEl.classList.add('k-rows-compact');
    headEl.classList.add('k-rows-compact');
    follow = false;
    drawStat();
    drawRows();
  }

  function close() {
    selected = null;
    detailSlot.replaceChildren();
    main.classList.remove('is-open');
    rowsEl.classList.remove('k-rows-compact');
    headEl.classList.remove('k-rows-compact');
    drawRows();
  }

  /* ---- server ---- */

  function poll() {
    fetch('api/records?since=' + lastSeq).then(function (res) {
      if (!res.ok) throw new Error(res.status);
      return res.json();
    }).then(function (batch) {
      if (!batch.length) return;
      for (var i = 0; i < batch.length; i++) {
        var r = batch[i];
        if (!byId.has(r.seq)) { records.push(r); byId.set(r.seq, r); }
        if (r.seq > lastSeq) lastSeq = r.seq;
        if (r.agent && r.agent.session_id) sessions.add(r.agent.session_id);
        if (r.tool && r.tool.name) tools.add(r.tool.name);
      }
      syncOptions();
      drawStat();
      drawRows();
    }).catch(function () {
      chain = { state: 'unknown', text: 'chain: server unreachable' };
      drawStat();
    });
  }

  function verify() {
    chain = { state: 'unknown' };
    drawStat();
    fetch('api/verify').then(function (res) { return res.json(); }).then(function (v) {
      chain = v.ok ? { state: 'ok', records: v.records }
        : { state: 'broken', line: v.line, error: v.error };
      drawStat();
    }).catch(function () {
      chain = { state: 'unknown', text: 'chain: server unreachable' };
      drawStat();
    });
  }

  headEl.replaceChildren(K.RecordRowHead());
  headEl.hidden = true;
  drawStat();
  poll();
  verify();
  setInterval(poll, 2000);
  setInterval(verify, 30000);
  window.addEventListener('resize', measureChrome);
})();
