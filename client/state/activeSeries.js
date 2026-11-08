import { replaceLibrary } from './library.js';

function archive(state) {
  const saved = { ...(state.seriesProgress || {}) };
  if(state.imdbID) saved[state.imdbID] = { watched:{...state.watched}, startedAt:state.startedAt, runtimeMin:state.runtimeMin };
  return saved;
}
function markSource(id) {
  replaceLibrary(movies => movies.map(movie => movie.isNow || movie.id === id ? {...movie,isNow:movie.id===id} : movie));
}
export function selectActiveSeries(state, movie, runtimeMin, now = Date.now()) {
  const id = movie.omdb?.imdbID;
  if(!id) throw new Error('Для сериала нужен IMDb ID. Выбери его через поиск.');
  const saved = archive(state);
  const previous = saved[id];
  markSource(movie.id);
  return { ...state, imdbID:id, sourceMovieId:movie.id || null, title:movie.name || '', posterUrl:movie.omdb?.posterUrl || null,
    startedAt:previous?.startedAt || now, runtimeMin:runtimeMin || previous?.runtimeMin || null,
    totalSeasons:null, watched:{...previous?.watched}, finishPromptedFor:null, finishDismissedFor:null, seriesProgress:saved };
}
export function clearActiveSeries(state) {
  markSource(null);
  return { ...state, seriesProgress:archive(state), sourceMovieId:null, imdbID:null, title:'', posterUrl:null, startedAt:null, totalSeasons:null, watched:{}, finishPromptedFor:null, finishDismissedFor:null };
}
