import { loadLibrary } from './library.js';
const PROFILE_KEY_V2 = "netfly_profile_v2";
let profileSnapshot;
const profileListeners = new Set();
let progressSnapshot, episodeCacheSnapshot;
const progressListeners = new Set(), cacheListeners = new Set();
export function getProgressSnapshot(){ return progressSnapshot ||= loadNowState(); }
export function subscribeProgress(listener){ progressListeners.add(listener); return () => progressListeners.delete(listener); }
export function getEpisodeCache(){ return episodeCacheSnapshot ||= readObject('netfly_omdb_eps_v1',globalThis.localStorage); }
export function subscribeEpisodeCache(listener){ cacheListeners.add(listener); return () => cacheListeners.delete(listener); }
export function saveEpisodeCache(cache){ globalThis.localStorage.setItem('netfly_omdb_eps_v1',JSON.stringify(cache)); episodeCacheSnapshot={...cache}; cacheListeners.forEach(listener=>listener()); }
export function getProfileSnapshot(){ return profileSnapshot ||= loadProfile(loadLibrary()); }
export function subscribeProfile(listener){ profileListeners.add(listener); return () => profileListeners.delete(listener); }
const NOW_KEY_V1 = "netfly_now_v1";
const normalize = value => String(value ?? "").trim().toLowerCase();
export function updateProfile(current, patch) {
  return { ...current, ...patch };
}
export function updateProgress(current, patch) {
  return { ...current, ...patch };
}
export function markEpisode(current, key, checked) {
  return { ...current, watched: { ...current.watched, [key]: !!checked } };
}
export function resetProgress(current) {
  return { ...current, watched: {}, watchLog: [], activityDays: [] };
}
export function recordActivity(current, day) {
  return { ...current, activityDays: [...new Set([...(current.activityDays || []), day])].sort() };
}
export function recordViewing(current, entry) {
  return { ...current, watchLog: [entry, ...(Array.isArray(current.watchLog) ? current.watchLog : [])].slice(0, 500) };
}
export function mergeServerProfile(local, remote) {
  return { ...local, ...remote, avatar: remote.avatar || local.avatar || null };
}
function readObject(key, storage){
  try { const value = JSON.parse(storage.getItem(key)); return value && typeof value === "object" && !Array.isArray(value) ? value : {}; } catch { return {}; }
}

export function loadProfile(movies = [], storage = globalThis.localStorage){
      const legacy = readObject("netfly_profile_v1", storage) || {};
      const p = readObject(PROFILE_KEY_V2, storage) || {};
      const src = Object.keys(p).length ? p : legacy;

      // Migration helpers: old version stored names instead of IDs
      function findRatedByName(name){
        const nn = normalize(name);
        if(!nn) return null;
        const rated = movies.filter(m => (m.status || "watched") === "watched");
        return rated.find(m => normalize(m.name) === nn) || null;
      }

      const out = {
        favDirectorName: String(src.favDirectorName || src.favDirector || ""),
        favActorName: String(src.favActorName || src.favActor || ""),
        favMovieId: src.favMovieId || null,
        favSeriesId: src.favSeriesId || null,
      };

      // if IDs missing, try map from legacy names
      if(!out.favMovieId && src.favMovie){
        const m = findRatedByName(src.favMovie);
        if(m) out.favMovieId = m.id;
      }
      if(!out.favSeriesId && src.favSeries){
        const m = findRatedByName(src.favSeries);
        if(m) out.favSeriesId = m.id;
      }

      out.tagline = String(src.tagline || "");
      out.manualGenres = Array.isArray(src.manualGenres) ? src.manualGenres.filter(Boolean).slice(0,2) : [];
      out.avatar = src.avatar || null;

      return out;
    }

    export function saveProfile(p, storage = globalThis.localStorage){
      storage.setItem(PROFILE_KEY_V2, JSON.stringify(p));
      if(storage === globalThis.localStorage){ profileSnapshot = { ...p }; profileListeners.forEach(listener => listener()); }
    }

export const criteria = [{key:'overall',label:'Общее'},{key:'engage',label:'Вовлечённость'},{key:'emotions',label:'Эмоции'}];
const score = movie => criteria.reduce((sum,{key})=>sum+Math.max(0,Math.min(10,Number(movie.scores?.[key])||0)),0)/3;
export function profileData(movies) {
  const rated=movies.filter(movie=>(movie.status || 'watched')==='watched');
  const averages=Object.fromEntries(criteria.map(({key})=>[key,rated.length?rated.reduce((sum,movie)=>sum+Math.max(0,Math.min(10,Number(movie.scores?.[key])||0)),0)/rated.length:null]));
  const top=criteria.slice().sort((a,b)=>(averages[b.key] || 0)-(averages[a.key] || 0))[0].key;
  const label={overall:'общее впечатление',engage:'вовлечённость',emotions:'эмоции'}[top];
  const decorate=movie=>({...movie,formattedScore:score(movie).toFixed(1)});
  return { rated, tiles:[{k:'Оценено',n:rated.length},{k:'Буду смотреть',n:movies.filter(movie=>movie.status==='wish').length},{k:'Избранное',n:movies.filter(movie=>movie.favorite).length},{k:'Средняя оценка',n:rated.length?(rated.reduce((sum,movie)=>sum+score(movie),0)/rated.length).toFixed(1):'—'}],
    scores:{criteria,averages,insight:rated.length?`Инсайт: ты чаще всего высоко оцениваешь ${label}.`:'Добавь оценки, чтобы увидеть инсайты.'},
    allGenres:[...new Set(rated.flatMap(movie=>String(movie.omdb?.genre || movie.genre || movie.genres || movie.omdbGenre || '').split(',').map(value=>value.trim()).filter(Boolean)))].sort((a,b)=>a.localeCompare(b,'ru')).slice(0,30),
    best:rated.slice().sort((a,b)=>score(b)-score(a)).slice(0,3).map(decorate),
    recent:rated.slice().sort((a,b)=>(b.createdAt || 0)-(a.createdAt || 0)).slice(0,3).map(decorate)
  };
}
    // ========= Now Watching storage =========
    export function loadNowState(storage = globalThis.localStorage){
      const p = readObject(NOW_KEY_V1, storage) || {};
      return {
        seriesProgress: p.seriesProgress && typeof p.seriesProgress === 'object' ? p.seriesProgress : {},
        imdbID: p.imdbID || null,
        title: p.title || "",
        posterUrl: p.posterUrl || null,
        sourceMovieId: p.sourceMovieId || null,
        finishPromptedFor: p.finishPromptedFor || null,
        finishDismissedFor: p.finishDismissedFor || null,
        startedAt: Number.isFinite(Number(p.startedAt)) ? Number(p.startedAt) : null,
        runtimeMin: Number.isFinite(Number(p.runtimeMin)) ? Number(p.runtimeMin) : null,
        totalSeasons: Number.isFinite(Number(p.totalSeasons)) ? Number(p.totalSeasons) : null,
        // watched: { "S1E1": true, ... }
        watched: (p.watched && typeof p.watched === "object") ? p.watched : {},
        // watchLog: [{ ts, eps, minutes }] (used for last-7-days stats / weekly goal)
        watchLog: Array.isArray(p.watchLog) ? p.watchLog : (
          Array.isArray(p.sessions) ? p.sessions.map(s => ({
            ts: Number(s.tsEnd || s.tsStart || 0) || 0,
            eps: Number(s.eps || 0) || 0,
            minutes: Number(s.minutes || 0) || 0
          })).filter(x => x.ts) : []
        ),
        // activity days for streak: ["YYYY-MM-DD", ...] (unique)
        activityDays: Array.isArray(p.activityDays) ? p.activityDays : [],
        // optional: streak enabled
        streakOn: (p.streakOn ?? true) ? true : false,
        // weekly goal episodes (0 = off)
        goalEps: Number.isFinite(Number(p.goalEps)) ? Number(p.goalEps) : 0,
      };
    }
    export function saveNowState(nowState, storage = globalThis.localStorage){
      storage.setItem(NOW_KEY_V1, JSON.stringify(nowState));
      if(storage === globalThis.localStorage){ progressSnapshot={...nowState}; progressListeners.forEach(listener=>listener()); }
    }
