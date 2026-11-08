import { createSeriesLoader } from './seriesLoader.js';
import { getEpisodeCache, saveEpisodeCache } from './profile.js';
import { omdbRequest } from '../api/omdb.js';

export function createSeriesEpisodes({ getProgress, patchProgress, parseRuntime, onCache }) {
  const loader = createSeriesLoader({
    request: omdbRequest,
    getCache: getEpisodeCache,
    saveCache: (id, entry) => {
      const cache = { ...getEpisodeCache(), [id]: entry };
      saveEpisodeCache(cache);
      onCache(cache);
    },
    onDetails: (id, details) => {
      const state = getProgress();
      if (state.imdbID !== id) return;
      const patch = {};
      if (!state.totalSeasons) patch.totalSeasons = Number(details.totalSeasons) || null;
      if (!state.runtimeMin) patch.runtimeMin = parseRuntime(details.Runtime);
      if (!state.posterUrl && details.Poster !== 'N/A') patch.posterUrl = details.Poster || null;
      if (!state.title && details.Title !== 'N/A') patch.title = details.Title || '';
      patchProgress(patch);
    },
  });
  return { load: () => {
    const state = getProgress();
    return loader.load(state.imdbID, state.totalSeasons);
  } };
}
