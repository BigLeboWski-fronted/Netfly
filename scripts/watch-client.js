require('esbuild').context({
  entryPoints: ['client/main.jsx'],
  bundle: true,
  outfile: 'public/assets/ui.js',
  format: 'iife',
  target: ['es2020'],
  define: { 'process.env.NODE_ENV': '"development"' },
}).then(context => context.watch()).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
