const views = new Set(['home','evaluate','rated','wish','search','now','profile','settings']);
export function pathForView(viewId, opts = {}) {
  if(viewId === 'person') return `/person/${encodeURIComponent(opts.personId)}`;
  if(viewId === 'movie') return `/movie/${encodeURIComponent(opts.tmdbId)}?type=${encodeURIComponent(opts.type || 'movie')}`;
  return viewId === 'home' ? '/' : `/${viewId}`;
}
export function parseRoute(location) {
  const path = location.pathname.replace(/\/+$/, '') || '/';
  if(/^\/person\/\d+$/.test(path)) return {viewId:'person',opts:{personId:path.split('/')[2]}};
  if(path.startsWith('/movie/')) {
    try {
      const tmdbId = decodeURIComponent(path.slice(7));
      if(tmdbId) return {viewId:'movie',opts:{tmdbId,type:new URLSearchParams(location.search).get('type') || 'movie'}};
    } catch { /* Malformed addresses fall back to the home page. */ }
  }
  const viewId = path === '/' ? 'home' : path.slice(1);
  return {viewId: views.has(viewId) ? viewId : 'home',opts:{}};
}
export function createRouter(target = window) {
  let route = parseRoute(target.location);
  const listeners = new Set();
  function publish(next) { route = next; listeners.forEach(listener => listener(route)); }
  function restore() {
    const next = parseRoute(target.location);
    const state = target.history.state;
    if(state?.viewId === next.viewId && state.openId) next.opts.openId = state.openId;
    publish(next);
  }
  target.addEventListener('popstate',restore);
  return {
    getSnapshot: () => route,
    read: () => parseRoute(target.location),
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    navigate(viewId, opts = {}) {
      const {fromHistory, ...state} = opts;
      if(!fromHistory) target.history.pushState({viewId,...state},'',pathForView(viewId,state));
      publish({viewId,opts:state});
    },
    restore,
    dispose() { target.removeEventListener('popstate',restore); listeners.clear(); },
  };
}
