// Shared library state boundary.
//
// The legacy application still owns the in-memory array for now, but all
// persistence goes through this module. React and the remaining legacy views
// can therefore subscribe to one storage contract while the migration is
// completed incrementally.

export const LIBRARY_STORAGE_KEY = 'netfly_movies_v6';

function parseMovies(raw) {
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

const listeners = new Set();
let currentMovies = null;

export function loadLibrary(storage = globalThis.localStorage) {
  if (currentMovies) return currentMovies;
  try {
    const raw = storage?.getItem(LIBRARY_STORAGE_KEY);
    currentMovies = raw ? parseMovies(raw) : [];
  } catch {
    currentMovies = [];
  }
  return currentMovies;
}

export function saveLibrary(movies, storage = globalThis.localStorage) {
  const value = Array.isArray(movies) ? movies : [];
  currentMovies = value;
  try {
    storage?.setItem(LIBRARY_STORAGE_KEY, JSON.stringify(value));
  } catch {
    // Storage can be unavailable in private browsing or constrained embeds.
  }
  listeners.forEach(listener => listener(value));
  if (typeof globalThis.dispatchEvent === 'function' && typeof globalThis.CustomEvent === 'function') {
    globalThis.dispatchEvent(new CustomEvent('netfly:library-change'));
  }
  return value;
}

export function addMovie(movie, storage = globalThis.localStorage) {
  return saveLibrary([...loadLibrary(storage), movie], storage);
}

export function replaceLibrary(nextOrUpdater, storage = globalThis.localStorage) {
  const current = loadLibrary(storage);
  const next = typeof nextOrUpdater === 'function' ? nextOrUpdater(current) : nextOrUpdater;
  return saveLibrary(next === current ? current.slice() : next, storage);
}

export function updateMovie(id, update, storage = globalThis.localStorage) {
  const movies = loadLibrary(storage);
  const index = movies.findIndex(item => String(item.id) === String(id));
  if (index < 0) return null;
  const next = movies.slice();
  const movie = { ...next[index] };
  next[index] = movie;
  const patch = typeof update === 'function' ? update(movie) : update;
  if (patch && patch !== movie && typeof patch === 'object') Object.assign(movie, patch);
  saveLibrary(next, storage);
  return movie;
}

export function removeMovie(id, storage = globalThis.localStorage) {
  const movies = loadLibrary(storage);
  const next = movies.filter(item => String(item.id) !== String(id));
  return saveLibrary(next, storage);
}

export function toggleMovieFavorite(id, storage = globalThis.localStorage) {
  return updateMovie(id, movie => {
    movie.favorite = !movie.favorite;
    return movie;
  }, storage);
}

export function subscribeLibrary(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function installLibraryBridge(target = globalThis) {
  currentMovies = loadLibrary(target.localStorage);
  target.NetflyLibrary = {
    key: LIBRARY_STORAGE_KEY,
    load: () => loadLibrary(target.localStorage),
    save: movies => saveLibrary(movies, target.localStorage),
    add: movie => addMovie(movie, target.localStorage),
    replace: nextOrUpdater => replaceLibrary(nextOrUpdater, target.localStorage),
    update: (id, update) => updateMovie(id, update, target.localStorage),
    remove: id => removeMovie(id, target.localStorage),
    toggleFavorite: id => toggleMovieFavorite(id, target.localStorage),
    subscribe: subscribeLibrary,
  };
}
