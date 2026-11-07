const fs = require('fs');
const vm = require('vm');
const cp = require('child_process');
for (const file of ['server/index.js', 'server/db.js', 'netlify/functions/api.js', 'public/sw.js']) {
  cp.execFileSync(process.execPath, ['--check', file]);
}
const html = fs.readFileSync('public/index.html', 'utf8');
for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) new vm.Script(match[1]);
JSON.parse(fs.readFileSync('public/manifest.json', 'utf8'));
require('esbuild').buildSync({
  entryPoints: ['client/main.jsx'],
  bundle: true,
  outfile: 'public/assets/ui.js',
  format: 'iife',
  target: ['es2020'],
  minify: true,
  define: { 'process.env.NODE_ENV': '"production"' },
});
console.log('Build passed: React bundle, frontend scripts, server, Netlify function and manifest validated.');
