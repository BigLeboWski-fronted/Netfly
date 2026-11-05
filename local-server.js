const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
};

function safePath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const relative = decoded === '/' ? '/index.html' : decoded;
  const filePath = path.resolve(PUBLIC_DIR, `.${relative}`);
  return filePath.startsWith(PUBLIC_DIR + path.sep) ? filePath : null;
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ ok: true, mode: 'local-static' }));
  }

  const filePath = safePath(req.url || '/');
  if (!filePath) {
    res.writeHead(400);
    return res.end('Bad request');
  }

  fs.stat(filePath, (statError, stats) => {
    const target = !statError && stats.isFile() ? filePath : path.join(PUBLIC_DIR, 'index.html');
    fs.readFile(target, (error, data) => {
      if (error) {
        res.writeHead(500);
        return res.end('Unable to read the site');
      }
      const type = MIME_TYPES[path.extname(target).toLowerCase()] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Netfly local server: http://localhost:${PORT}`);
});

