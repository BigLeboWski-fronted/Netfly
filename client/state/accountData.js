import { loadLibrary, replaceLibrary } from './library.js';
import { loadProfile, mergeServerProfile, saveProfile, loadNowState, updateProgress, saveNowState, getEpisodeCache, saveEpisodeCache } from './profile.js';
import { getSessionVersion } from './session.js';

export function createAccountDataLoader({ request, onApplying, onLoaded, onPending, storage=globalThis.localStorage }) {
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
      const snapshot={movies,profile,nowState,cache};
      onLoaded(snapshot);
      if(pending) onPending();
      return snapshot;
    } finally {onApplying(false);}
  }
  return {load,cancel(){generation++;}};
}
