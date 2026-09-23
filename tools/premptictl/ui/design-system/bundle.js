/* @ds-bundle: {"format":4,"namespace":"Kebnetrails","components":[{"name":"VerdictBadge"},{"name":"ChainStatus"},{"name":"ToolCall"},{"name":"RecordRow"},{"name":"FilterBar"},{"name":"RecordDetail"},{"name":"StatBar"}]} */
(function (root) {
  'use strict';

  /* ---------- primitives ---------- */

  var ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ESC[c]; }); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /* ---------- danger patterns ---------- */

  // Substrings that earned a verdict often enough to be worth marking on sight.
  // Consumers may replace this array; every entry is a RegExp with the g flag.
  var DANGER = [
    /\brm\s+-[a-z]*[rf][a-z]*\b/g,
    /\bsudo\b/g,
    /\bchmod\s+(?:-R\s+)?777\b/g,
    /\bcurl\b[^|;&]*\|\s*(?:ba|z|)sh\b/g,
    /\b(?:eval|source)\s/g,
    /\bbase64\s+-{1,2}d(?:ecode)?\b/g,
    /--(?:force|no-verify|hard)\b/g,
    /(?:^|[\s"'/])(?:\.env(?:\.[\w-]+)?|id_[a-z]+|credentials|secrets?\.(?:env|json|ya?ml))\b/g,
    /(?:~\/\.ssh|\/etc\/(?:passwd|shadow|sudoers))\b/g,
    /\bgit\s+push\b[^|;&]*--force/g,
    />\s*\/dev\/sd[a-z]\b/g
  ];

  /* ---------- tokenizers: emit [start, end, class] over the source text ---------- */

  var BASH_BREAK = /^(?:\|\||&&|;;|[|;&(){}\n])$/;

  function tokenizeBash(s) {
    var out = [], i = 0, n = s.length, atHead = true;
    function push(a, b, c) { if (b > a) out.push([a, b, c]); }
    while (i < n) {
      var ch = s[i];
      if (ch === ' ' || ch === '\t' || ch === '\n') { if (ch === '\n') atHead = true; i++; continue; }
      if (ch === '#' && (i === 0 || /\s/.test(s[i - 1]))) {
        var e = s.indexOf('\n', i); e = e < 0 ? n : e; push(i, e, 'punct'); i = e; continue;
      }
      if (ch === '"' || ch === "'") {
        var q = i + 1;
        while (q < n && s[q] !== ch) { if (s[q] === '\\' && ch === '"') q++; q++; }
        push(i, Math.min(q + 1, n), 'string'); i = q + 1; atHead = false; continue;
      }
      if (ch === '$') {
        var m = /^\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_][\w]*|[?#@*!$0-9])/.exec(s.slice(i));
        if (m) { push(i, i + m[0].length, 'literal'); i += m[0].length; atHead = false; continue; }
      }
      var op = /^(?:\|\||&&|>>|2>&1|<<|[|;&<>()=])/.exec(s.slice(i));
      if (op) {
        push(i, i + op[0].length, 'punct');
        if (BASH_BREAK.test(op[0]) || op[0] === '&&' || op[0] === '||') atHead = true;
        i += op[0].length; continue;
      }
      var w = /^[^\s|;&<>()"'$]+/.exec(s.slice(i));
      if (!w) { i++; continue; }
      var t = w[0], cls;
      if (atHead) cls = 'cmd';
      else if (t[0] === '-') cls = 'key';
      else if (/^-?\d+(?:\.\d+)?$/.test(t)) cls = 'number';
      else if (/[/~]/.test(t) || /^[\w.-]+\.[a-z]{2,4}$/i.test(t)) cls = 'string';
      else cls = 'plain';
      push(i, i + t.length, cls);
      i += t.length;
      atHead = false;
    }
    return out;
  }

  var JSON_RE = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)|\b(true|false|null)\b|([{}[\],:])/g;

  function tokenizeJson(s) {
    var out = [], m;
    JSON_RE.lastIndex = 0;
    while ((m = JSON_RE.exec(s))) {
      if (m[1]) out.push([m.index, m.index + m[1].length, m[2] ? 'key' : 'string']);
      if (m[2]) out.push([m.index + m[1].length, JSON_RE.lastIndex, 'punct']);
      else if (m[3]) out.push([m.index, JSON_RE.lastIndex, 'number']);
      else if (m[4]) out.push([m.index, JSON_RE.lastIndex, 'literal']);
      else if (m[5]) out.push([m.index, JSON_RE.lastIndex, 'punct']);
    }
    return out;
  }

  function sniff(text, toolName) {
    if (/^(Bash|bash|shell)$/.test(toolName || '')) return 'bash';
    var t = (text || '').trim();
    if ((t[0] === '{' || t[0] === '[') && /[:,]/.test(t)) return 'json';
    return 'bash';
  }

  /* ---------- highlight ---------- */

  // highlight(text, {lang, tool, danger, pretty}) -> {html, lang, text}
  function highlight(text, opts) {
    opts = opts || {};
    var src = String(text == null ? '' : text);
    var lang = opts.lang || sniff(src, opts.tool);
    if (lang === 'json' && opts.pretty !== false) {
      try { src = JSON.stringify(JSON.parse(src), null, 2); } catch (_) { /* leave as written */ }
    }
    var toks = lang === 'json' ? tokenizeJson(src) : tokenizeBash(src);
    var cuts = [];
    var pats = opts.danger === false ? [] : (opts.danger || DANGER);
    for (var p = 0; p < pats.length; p++) {
      var re = pats[p], m;
      re.lastIndex = 0;
      while ((m = re.exec(src))) { cuts.push([m.index, m.index + m[0].length]); if (!m[0].length) re.lastIndex++; }
    }
    var html = '', at = 0;
    function paint(a, b, cls) {
      if (b <= a) return;
      var hit = null;
      for (var c = 0; c < cuts.length; c++) if (cuts[c][0] < b && cuts[c][1] > a) { hit = cuts[c]; break; }
      if (!hit) { html += '<span class="k-syn-' + cls + '">' + esc(src.slice(a, b)) + '</span>'; return; }
      paint(a, Math.max(a, hit[0]), cls);
      var s2 = Math.max(a, hit[0]), e2 = Math.min(b, hit[1]);
      // A short match (sudo, .env, --force) turns red. A whole flagged clause
      // keeps its syntax colours and takes a red underline instead — a pipeline
      // painted entirely red is less readable, not more alarming.
      if (hit[1] - hit[0] <= 24) html += '<mark class="k-syn-danger">' + esc(src.slice(s2, e2)) + '</mark>';
      else html += '<mark class="k-syn-danger k-syn-clause"><span class="k-syn-' + cls + '">' + esc(src.slice(s2, e2)) + '</span></mark>';
      paint(e2, b, cls);
    }
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      if (t[0] > at) paint(at, t[0], 'plain');
      paint(t[0], t[1], t[2]);
      at = t[1];
    }
    if (at < src.length) paint(at, src.length, 'plain');
    return { html: html, lang: lang, text: src };
  }

  /* ---------- record helpers ---------- */

  var VERDICTS = ['allow', 'ask', 'deny', 'defer', 'none'];

  // One line that says what the call actually does, for the row.
  function summarize(record) {
    var t = (record && record.tool) || {}, s = t.input || '';
    try {
      var j = JSON.parse(s);
      s = j.command || j.file_path || j.pattern || j.url || j.prompt || j.description || s;
      if (typeof s !== 'string') s = JSON.stringify(s);
    } catch (_) { /* not JSON: the raw input is the summary */ }
    return String(s).replace(/\s+/g, ' ').trim();
  }

  function verdictOf(record) { return ((record && record.final) || {}).verdict || 'none'; }

  // A shell tool's input arrives as a JSON envelope around the command. Show
  // the command as shell, and the rest of the envelope as a trailing note —
  // running the bash tokenizer over the raw JSON reads as neither language.
  function payloadOf(input, lang) {
    var text = String(input == null ? '' : input), extras = [];
    if (lang === 'json') return { text: text, lang: 'json', extras: extras };
    try {
      var j = JSON.parse(text);
      if (j && typeof j === 'object' && !Array.isArray(j) && typeof j.command === 'string') {
        Object.keys(j).forEach(function (k) {
          if (k === 'command') return;
          extras.push(k + ' ' + (typeof j[k] === 'string' ? j[k] : JSON.stringify(j[k])));
        });
        return { text: j.command, lang: 'bash', extras: extras };
      }
    } catch (_) { /* not an envelope: highlight what was given */ }
    return { text: text, lang: lang || null, extras: extras };
  }

  /* ---------- components ---------- */

  function VerdictBadge(props) {
    props = props || {};
    var v = VERDICTS.indexOf(props.verdict) < 0 ? 'none' : props.verdict;
    var n = el('span', 'k-badge k-badge-' + v, props.label || v);
    n.setAttribute('data-verdict', v);
    if (props.title) n.title = props.title;
    if (props.source) {
      var wrap = el('span', 'k-badge-pair');
      wrap.appendChild(n);
      wrap.appendChild(el('span', 'k-meta', props.source));
      return wrap;
    }
    return n;
  }

  function ChainStatus(props) {
    props = props || {};
    var state = props.state || 'unknown';
    var text = props.text || (state === 'ok' ? 'chain ok · ' + (props.records || 0) + ' records'
      : state === 'broken' ? 'chain BROKEN at line ' + props.line + (props.error ? ': ' + props.error : '')
      : 'chain checking…');
    var n = el('span', 'k-chain k-chain-' + state);
    n.appendChild(el('span', 'k-chain-dot'));
    n.appendChild(el('span', null, text));
    n.setAttribute('role', 'status');
    return n;
  }

  // The tool call itself: header line, highlighted body, collapse past maxLines.
  function ToolCall(props) {
    props = props || {};
    var pay = payloadOf(props.input, props.lang);
    var res = highlight(pay.text, { lang: pay.lang, tool: props.tool, danger: props.danger });
    var root_ = el('div', 'k-toolcall');
    var head = el('div', 'k-toolcall-head');
    head.appendChild(el('span', 'k-toolcall-tool', props.tool || 'tool'));
    if (res.lang === 'json') head.appendChild(el('span', 'k-toolcall-lang', 'json'));
    if (props.verdict) head.appendChild(VerdictBadge({ verdict: props.verdict }));
    if (props.actions !== false) {
      var copy = el('button', 'k-btn k-btn-quiet', 'copy');
      copy.type = 'button';
      copy.onclick = function () {
        var done = function () { copy.textContent = 'copied'; setTimeout(function () { copy.textContent = 'copy'; }, 1200); };
        if (navigator.clipboard) navigator.clipboard.writeText(res.text).then(done, function () {}); else done();
      };
      head.appendChild(copy);
    }
    root_.appendChild(head);
    var pre = el('pre', 'k-code');
    var code = el('code');
    code.innerHTML = res.html;
    pre.appendChild(code);
    root_.appendChild(pre);
    if (pay.extras.length) root_.appendChild(el('div', 'k-meta k-toolcall-extras', pay.extras.join(' · ')));
    var lines = res.text.split('\n').length, max = props.maxLines == null ? 12 : props.maxLines;
    if (lines > max) {
      pre.classList.add('k-code-clamped');
      pre.style.setProperty('--k-clamp', max);
      var more = el('button', 'k-btn k-btn-quiet k-toolcall-more', 'show all ' + lines + ' lines');
      more.type = 'button';
      more.onclick = function () {
        var open = pre.classList.toggle('k-code-clamped');
        more.textContent = open ? 'show all ' + lines + ' lines' : 'collapse';
      };
      root_.appendChild(more);
    }
    return root_;
  }

  // A row in the trail. A grid, not a table cell run: the summary column is the
  // only elastic one, so nothing pushes the verdict off screen.
  function RecordRow(props) {
    props = props || {};
    var r = props.record || {}, a = r.agent || {}, t = r.tool || {}, f = r.falco || {}, l = r.llm || {}, fin = r.final || {};
    var v = verdictOf(r);
    var row = el('div', 'k-row k-row-' + v + (props.selected ? ' is-selected' : ''));
    row.tabIndex = 0;
    row.setAttribute('role', 'button');
    row.setAttribute('aria-expanded', props.selected ? 'true' : 'false');
    row.appendChild(el('span', 'k-lane'));
    var ts = r.ts_ms ? new Date(r.ts_ms) : null;
    var time = el('span', 'k-cell k-meta k-time', ts ? ts.toLocaleTimeString([], { hour12: false }) : '');
    if (ts) time.title = ts.toLocaleString([], { hour12: false });
    row.appendChild(time);
    row.appendChild(el('span', 'k-cell k-meta k-seq', r.seq == null ? '' : '#' + r.seq));
    var who = el('span', 'k-cell k-meta k-session', (a.session_id || '').slice(0, 8) + (a.agent_type ? '/' + a.agent_type : ''));
    who.title = a.session_id || '';
    row.appendChild(who);
    row.appendChild(el('span', 'k-cell k-tool', t.name || ''));
    var sum = el('span', 'k-cell k-summary');
    var hl = highlight(summarize(r), { tool: t.name, danger: props.danger });
    sum.innerHTML = hl.html;
    sum.title = summarize(r);
    row.appendChild(sum);
    var signals = el('span', 'k-cell k-signals');
    signals.appendChild(VerdictBadge({
      verdict: f.verdict || 'none',
      label: 'falco ' + (f.verdict || 'none'),
      title: (f.rules || []).map(function (x) { return x.rule; }).join('\n')
    }));
    var st = l.status || 'disabled';
    if (st === 'ok') signals.appendChild(VerdictBadge({ verdict: l.verdict, label: 'llm ' + l.verdict, title: l.reason }));
    else signals.appendChild(el('span', 'k-meta' + (st.indexOf('error') === 0 ? ' k-llm-error' : ''), 'llm ' + st));
    row.appendChild(signals);
    row.appendChild(VerdictBadge({ verdict: v, source: fin.source, title: fin.reason }));
    function fire() { if (props.onSelect) props.onSelect(r.seq, r); }
    row.onclick = fire;
    row.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fire(); } };
    return row;
  }

  // The column headings for a run of RecordRows. Same grid, so the labels
  // cannot drift out of step with the cells.
  function RecordRowHead() {
    var row = el('div', 'k-row k-row-head');
    row.appendChild(el('span', 'k-lane'));
    var cols = [['time', 'k-time'], ['#', 'k-seq'], ['session', 'k-session'], ['tool', 'k-tool'],
      ['call', 'k-summary'], ['signals', 'k-signals'], ['final', 'k-final']];
    cols.forEach(function (c) { row.appendChild(el('span', 'k-cell ' + c[1], c[0])); });
    return row;
  }

  function FilterBar(props) {
    props = props || {};
    var state = Object.assign({ q: '', final: '', source: '', llm: '', session: '', tool: '' }, props.value || {});
    var bar = el('div', 'k-filters');
    var search = el('input', 'k-input k-input-search');
    search.type = 'search';
    search.placeholder = props.placeholder || 'search command, rule, reason, session…';
    search.value = state.q;
    search.setAttribute('aria-label', 'Search the audit trail');
    bar.appendChild(search);
    var defs = [
      ['final', 'final', VERDICTS.slice(0, 4)],
      ['source', 'source', ['falco', 'llm', 'floor', 'monitor', 'passthrough', 'reaper', 'broker']],
      ['llm', 'llm', ['ok', 'error', 'skipped', 'disabled']],
      ['session', 'session', props.sessions || []],
      ['tool', 'tool', props.tools || []]
    ];
    var controls = {};
    defs.forEach(function (d) {
      var label = el('label', 'k-field');
      label.appendChild(el('span', 'k-field-label', d[1]));
      var sel = el('select', 'k-select');
      sel.appendChild(new Option('any', ''));
      d[2].forEach(function (v) { sel.appendChild(new Option(v.length > 14 ? v.slice(0, 14) + '…' : v, v)); });
      sel.value = state[d[0]] || '';
      label.appendChild(sel);
      bar.appendChild(label);
      controls[d[0]] = sel;
    });
    var clear = el('button', 'k-btn k-btn-quiet', 'clear');
    clear.type = 'button';
    bar.appendChild(clear);
    function emit() {
      state.q = search.value;
      Object.keys(controls).forEach(function (k) { state[k] = controls[k].value; });
      var active = Object.keys(state).filter(function (k) { return state[k]; }).length;
      clear.hidden = !active;
      if (props.onChange) props.onChange(Object.assign({}, state));
    }
    search.addEventListener('input', emit);
    Object.keys(controls).forEach(function (k) { controls[k].addEventListener('change', emit); });
    clear.onclick = function () {
      search.value = '';
      Object.keys(controls).forEach(function (k) { controls[k].value = ''; });
      emit();
    };
    clear.hidden = true;
    return bar;
  }

  function kv(dl, term, node) {
    dl.appendChild(el('dt', 'k-meta', term));
    var dd = el('dd', 'k-dd');
    if (typeof node === 'string') dd.textContent = node; else if (node) dd.appendChild(node);
    dl.appendChild(dd);
    return dd;
  }

  function RecordDetail(props) {
    props = props || {};
    var r = props.record || {}, a = r.agent || {}, t = r.tool || {}, l = r.llm || {}, f = r.falco || {}, fin = r.final || {};
    var panel = el('aside', 'k-detail');
    panel.setAttribute('aria-label', 'Record ' + (r.seq || ''));
    var head = el('div', 'k-detail-head');
    head.appendChild(el('h2', 'k-title', 'record #' + (r.seq == null ? '' : r.seq)));
    head.appendChild(el('span', 'k-meta', (r.ts_ms ? new Date(r.ts_ms).toLocaleString([], { hour12: false }) : '') + (r.latency_ms != null ? ' · ' + r.latency_ms + ' ms' : '')));
    var close = el('button', 'k-btn k-btn-quiet k-detail-close', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Close record detail');
    close.onclick = function () { if (props.onClose) props.onClose(); };
    head.appendChild(close);
    panel.appendChild(head);

    var verdict = el('div', 'k-detail-verdict');
    verdict.appendChild(VerdictBadge({ verdict: fin.verdict, source: 'via ' + (fin.source || '?') }));
    if (fin.reason) verdict.appendChild(el('p', 'k-reason', fin.reason));
    panel.appendChild(verdict);

    panel.appendChild(ToolCall({ tool: t.name, input: t.input, maxLines: props.maxLines == null ? 24 : props.maxLines }));

    var dl = el('dl', 'k-kv');
    var falco = el('div', 'k-stack');
    falco.appendChild(VerdictBadge({ verdict: f.verdict || 'none' }));
    (f.rules || []).forEach(function (x) {
      var rule = el('div', 'k-rule');
      rule.appendChild(el('span', 'k-rule-name', (x.kind ? x.kind + ' · ' : '') + x.rule));
      rule.appendChild(el('span', 'k-meta', x.message || ''));
      falco.appendChild(rule);
    });
    kv(dl, 'falco', falco);

    var llm = el('div', 'k-stack');
    var line = el('div', 'k-stack-line');
    if (l.verdict) line.appendChild(VerdictBadge({ verdict: l.verdict }));
    line.appendChild(el('span', 'k-meta', [l.status, l.model, l.latency_ms != null ? l.latency_ms + ' ms' : null,
      l.attempts ? l.attempts + ' attempt' + (l.attempts > 1 ? 's' : '') : null].filter(Boolean).join(' · ')));
    llm.appendChild(line);
    if (l.reason) llm.appendChild(el('p', 'k-reason', l.reason));
    if (l.roe_clause) llm.appendChild(el('p', 'k-meta', 'RoE: ' + l.roe_clause));
    kv(dl, 'llm monitor', llm);

    kv(dl, 'agent', [a.name, a.pid != null ? 'pid ' + a.pid : null, a.permission_mode ? 'mode ' + a.permission_mode : null,
      a.agent_type ? 'subagent ' + a.agent_type : null].filter(Boolean).join(' · '));
    kv(dl, 'session', a.session_id || '');
    kv(dl, 'cwd', r.cwd || '');
    var chain = el('div', 'k-stack');
    chain.appendChild(el('code', 'k-hash', 'hash ' + (r.hash || '')));
    chain.appendChild(el('code', 'k-hash', 'prev ' + (r.prev_hash || '')));
    if (t.input_sha256) chain.appendChild(el('code', 'k-hash', 'input ' + t.input_sha256));
    kv(dl, 'chain', chain);
    panel.appendChild(dl);
    return panel;
  }

  function StatBar(props) {
    props = props || {};
    var s = props.stats || {};
    var bar = el('header', 'k-statbar');
    bar.appendChild(el('h1', 'k-title', props.title || 'Kebnetrails audit trail'));
    var counts = el('div', 'k-counts');
    ['allow', 'ask', 'deny', 'defer'].forEach(function (v) {
      var g = el('span', 'k-count k-count-' + v);
      g.appendChild(el('b', null, String(s[v] || 0)));
      g.appendChild(el('span', 'k-meta', v));
      counts.appendChild(g);
    });
    var total = el('span', 'k-count');
    total.appendChild(el('b', null, String(s.total || 0)));
    total.appendChild(el('span', 'k-meta', 'records'));
    counts.insertBefore(total, counts.firstChild);
    bar.appendChild(counts);
    var tools = el('div', 'k-tools');
    if (props.chain) tools.appendChild(ChainStatus(props.chain));
    (props.actions || []).forEach(function (act) {
      var b = el('button', 'k-btn' + (act.active ? ' is-on' : ''), act.label);
      b.type = 'button';
      b.setAttribute('aria-pressed', act.active ? 'true' : 'false');
      b.onclick = function () { if (act.onClick) act.onClick(b); };
      tools.appendChild(b);
    });
    bar.appendChild(tools);
    return bar;
  }

  root.Kebnetrails = {
    esc: esc,
    DANGER: DANGER,
    highlight: highlight,
    summarize: summarize,
    verdictOf: verdictOf,
    VerdictBadge: VerdictBadge,
    ChainStatus: ChainStatus,
    ToolCall: ToolCall,
    RecordRow: RecordRow,
    RecordRowHead: RecordRowHead,
    FilterBar: FilterBar,
    RecordDetail: RecordDetail,
    StatBar: StatBar
  };
})(window);
