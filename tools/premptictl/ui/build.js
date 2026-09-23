// Assembles the single-file audit UI from the design-system sources.
//   node build.js            -> writes tools/premptictl/src/audit_ui.html
//   node build.js --preview  -> also writes preview.html with stubbed fetch
const fs = require('fs');
const p = require('path');

const BUILD = __dirname;
const DS = p.join(BUILD, 'design-system');
const OUT = p.join(BUILD, '..', 'src', 'audit_ui.html');

const read = (f) => fs.readFileSync(f, 'utf8');

// A stray closing script tag or comment opener in a source that gets inlined
// into a <script> would end the element early; refuse rather than emit a
// broken page.
const readScript = (f) => {
  const text = read(f);
  for (const bad of ['</script', '<!--']) {
    if (text.includes(bad)) throw new Error(p.basename(f) + ' contains ' + bad);
  }
  return text;
};

// Inserted verbatim: a plain replacement string would let `$'` and friends in
// the sources act as replacement patterns.
const put = (html, slot, text) => html.replace(slot, () => text);

let html = read(p.join(BUILD, 'shell.html'));
html = put(html, '/*__TOKENS_CSS__*/', read(p.join(BUILD, 'tokens.css')));
html = put(html, '/*__BUNDLE_CSS__*/', read(p.join(DS, 'bundle.css')));
html = put(html, '/*__PAGE_CSS__*/', read(p.join(BUILD, 'page.css')));
html = put(html, '/*__BUNDLE_JS__*/', readScript(p.join(DS, 'bundle.js')));
html = put(html, '/*__APP_JS__*/', readScript(p.join(BUILD, 'app.js')));

if (html.includes('__')) {
  const left = html.match(/\/\*__[A-Z_]+__\*\//g);
  if (left) throw new Error('unreplaced placeholders: ' + left.join(', '));
}

fs.writeFileSync(OUT, html);
console.log('wrote ' + OUT + ' (' + html.length + ' bytes)');

if (process.argv.includes('--preview')) {
  const demo = readScript(p.join(BUILD, 'demo.js'));
  const anchor = '/* Kebnetrails audit UI — page logic.';
  const preview = put(html, anchor, demo + '\n' + anchor);
  const out = p.join(BUILD, 'preview.html');
  fs.writeFileSync(out, preview);
  console.log('wrote ' + out);
}
