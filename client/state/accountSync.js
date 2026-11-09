import { loadLibrary, replaceLibrary } from './library.js';
import { loadProfile, mergeServerProfile, saveProfile, loadNowState, updateProgress, saveNowState, getEpisodeCache, saveEpisodeCache, subscribeProfile, getProfileSnapshot } from './profile.js';
import { configureSession, restoreSession, getSessionVersion, setUser } from './session.js';
import { accountRequest } from '../api/account.js';

let authenticate;

export async function authenticateAccount(data) {
  if (!authenticate) throw new Error('Авторизация ещё загружается. Попробуй снова.');
  if (!data || typeof data.username !== 'string' || !data.username.trim()) {
    throw new Error('Сервер не подтвердил вход. Проверь, что запущен полный сервер приложения.');
  }
  return authenticate(data);
}

function createAccountDataLoader({ request, onApplying, onLoaded, onPending, storage=globalThis.localStorage }) {
  let generation=0;
  async function load() {
    const version=++generation, session=getSessionVersion();
    const data=await request('/api/data');
    if(version!==generation || session!==getSessionVersion()) return null;
    const pending=storage.getItem('netfly_library_pending')==='1';
    onApplying(true);
    try {
      let movies=loadLibrary();
      if(!pending && Array.isArray(data.movies) && data.movies.length) movies=replaceLibrary(data.movies);
      let profile=loadProfile(movies,storage);
      if(data.profile && Object.keys(data.profile).length) { profile=mergeServerProfile(profile,data.profile); saveProfile(profile,storage); }
      let nowState=loadNowState(storage);
      if(data.now_state && Object.keys(data.now_state).length){ nowState=updateProgress(nowState,data.now_state); saveNowState(nowState,storage); }
      let cache=getEpisodeCache();
      if(data.omdb_ep_cache && Object.keys(data.omdb_ep_cache).length){ cache={...cache,...data.omdb_ep_cache}; saveEpisodeCache(cache); }
      const snapshot={movies,profile,nowState,cache,updatedAt:data.updated_at || null};
      onLoaded(snapshot);
      if(pending) onPending();
      return snapshot;
    } finally {onApplying(false);}
  }
  return {load,cancel(){generation++;}};
}

function createSync({ request, getSnapshot, isAuthenticated, onStatus, onSaved, delay = 3000 }) {
  let timer = null;
  let running = null;
  let queued = false;
  async function flush() {
    clearTimeout(timer);
    timer = null;
    if (!isAuthenticated()) return;
    if (running) { queued = true; return running; }
    const snapshot = JSON.stringify(getSnapshot());
    onStatus('syncing');
    running = (async () => {
      try {
        const result = await request('/api/data', { method: 'PUT', body: snapshot });
        onStatus('ok');
        onSaved?.(JSON.parse(snapshot), result);
      } catch (error) {
        onStatus('err');
        console.warn('syncToServer:', error.message);
      }
    })();
    try { await running; } finally {
      running = null;
      if (queued) { queued = false; return flush(); }
    }
  }
  function schedule() {
    if (!isAuthenticated()) return;
    clearTimeout(timer);
    timer = setTimeout(flush, delay);
  }
  function cancel() { clearTimeout(timer); timer = null; queued = false; }
  return { flush, schedule, cancel };
}

// Coordinates account hydration and debounced persistence without depending on
// the legacy page controller's global variables.
export function createAccountSync({ request, getSession, getSnapshot, onApplying, onLoaded, onStatus, onSaved, onLibraryChange, onProfileChange }) {
  let loading = false;
  const loader = createAccountDataLoader({
    request,
    onApplying: value => { loading = value; onApplying?.(value); },
    onLoaded,
    onPending: () => sync.schedule(),
  });
  const sync = createSync({
    request,
    getSnapshot,
    isAuthenticated: () => !!getSession()?.user,
    onStatus,
    onSaved,
  });
  return {
    loader,
    sync,
    isLoading: () => loading,
    load: () => loader.load(),
    schedule: () => sync.schedule(),
    flush: () => sync.flush(),
    cancel: () => { loader.cancel(); sync.cancel(); },
    bindLibraryChanges: (target = globalThis, storage = globalThis.localStorage) => {
      const listener = () => {
        onLibraryChange?.();
        if (loading) return;
        try { storage.setItem('netfly_library_pending', '1'); } catch {}
        sync.schedule();
      };
      target.addEventListener?.('netfly:library-change', listener);
      return () => target.removeEventListener?.('netfly:library-change', listener);
    },
    wrapSave: save => (...args) => {
      const result = save(...args);
      sync.schedule();
      return result;
    },
    bindProfileChanges: () => subscribeProfile(() => {
      onProfileChange?.(getProfileSnapshot());
      if (!loading) sync.schedule();
    }),
  };
}

export function createAccountSession({ sync, onLoaded, target = globalThis }) {
  function anonymous() {
    sync.cancel();
    setUser(null);
  }
  async function authenticated(data) {
    target.dispatchEvent(new Event('netfly:session-ready'));
    setUser(data.username);
    try { await sync.load(); }
    catch (error) { console.warn('loadFromServer:', error.message); }
    onLoaded?.();
  }
  configureSession({ logout: async () => {
    await accountRequest('/api/logout', { method: 'POST' }).catch(() => {});
    anonymous();
  } });
  authenticate = authenticated;
  return {
    authenticated,
    restore: () => restoreSession({ request: accountRequest, onAnonymous: anonymous, onAuthenticated: authenticated }),
  };
}
