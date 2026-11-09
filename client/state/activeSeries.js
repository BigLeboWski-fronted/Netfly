import { loadLibrary, replaceLibrary } from './library.js';

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

export function createActiveSeriesActions({ getState, setState, save, parseRuntime, toast, onRate, onDraft }) {
  const commit = state => { setState(state); save(); };
  function clear() { commit(clearActiveSeries(getState())); }
  function select(movie) {
    if (!movie) return;
    try {
      const state = selectActiveSeries(getState(), movie, parseRuntime(movie.omdb?.runtime));
      commit(state);
      toast('Смотрю сейчас', state.title);
    } catch (error) { toast(error.message); }
  }
  function rate() {
    const state = getState();
    if (!state.imdbID) return;
    const source = loadLibrary().find(movie => movie.id === state.sourceMovieId || movie.omdb?.imdbID === state.imdbID);
    clear();
    if (source) onRate(source);
    else onDraft({ name: state.title || '', status: 'watched' }, {
      imdbID: state.imdbID, posterUrl: state.posterUrl, type: 'series',
      runtime: state.runtimeMin ? `${state.runtimeMin} min` : null,
    });
  }
  return { select, clear, rate };
}
