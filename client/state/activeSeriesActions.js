import { selectActiveSeries, clearActiveSeries } from './activeSeries.js';
import { loadLibrary } from './library.js';

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
