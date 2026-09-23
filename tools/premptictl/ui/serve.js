// Loopback static server for eyeballing preview.html. Not part of the build.
const http = require('http');
const fs = require('fs');
const p = require('path');
const ROOT = __dirname;
http.createServer((req, res) => {
  const name = p.basename((req.url || '/').split('?')[0]) || 'preview.html';
  const file = p.join(ROOT, name === '' ? 'preview.html' : name);
  fs.readFile(file, (err, body) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': name.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain' });
    res.end(body);
  });
}).listen(8731, '127.0.0.1', () => console.log('serving on http://127.0.0.1:8731/preview.html'));
