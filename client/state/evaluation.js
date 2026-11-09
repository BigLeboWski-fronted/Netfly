import { loadLibrary, addMovie, updateMovie } from './library.js';
import { omdbRequest } from '../api/omdb.js';
import { createOmdbSearch } from './omdbSearch.js';

export function createEvaluationDraft() {
  return { name: '', director: '', year: '', status: 'watched', tags: '', notes: '' };
}

export function evaluationFromMovie(movie) {
  return {
    editingId: movie.id,
    draft: {
      name: movie.name || '', director: movie.director || '', year: movie.year ?? '',
      status: movie.status && movie.status !== 'wish' ? movie.status : 'watched',
      tags: Array.isArray(movie.tags) ? movie.tags.join(', ') : '', notes: movie.notes || '',
    },
    metadata: movie.omdb ? { ...movie.omdb } : null,
    scores: Object.fromEntries(['overall', 'engage', 'emotions'].map(key => [key, Math.max(0, Math.min(10, Number(movie.scores?.[key]) || 0))])),
  };
}

export function fromTmdb(movie, type) {
  const name=movie.title || movie.name || 'Без названия';
  const runtime=movie.runtime || movie.episode_run_time?.[0];
  const director=movie.credits?.crew?.find(person=>person.job==='Director')?.name || '';
  return { draft:{...createEvaluationDraft(),name,director,year:(movie.release_date || movie.first_air_date || '').slice(0,4)}, metadata:{ title:name,tmdbId:movie.id,mediaType:type,imdbID:movie.external_ids?.imdb_id || `tmdb-${type}-${movie.id}`,posterUrl:movie.poster_path?'/api/tmdb/image/w500'+movie.poster_path:null,backdropUrl:movie.backdrop_path?'/api/tmdb/image/original'+movie.backdrop_path:null,type:type==='tv'?'series':'movie',genre:(movie.genres || []).map(item=>item.name).join(', '),runtime:runtime?runtime+' min':null,imdbRating:Number.isFinite(movie.vote_average)?movie.vote_average.toFixed(1):'—',actors:(movie.credits?.cast || []).slice(0,10).map(person=>person.name),plot:movie.overview || ''} };
}
export function fromOmdb(data) {
  const value=key=>data[key] && data[key]!=='N/A'?data[key]:null;
  return { draft:{ name:value('Title'),director:value('Director'),year:String(value('Year') || '').match(/\d{4}/)?.[0] || null },metadata:{ title:value('Title'),imdbID:value('imdbID'),posterUrl:value('Poster'),genre:value('Genre'),runtime:value('Runtime'),imdbRating:value('imdbRating'),type:value('Type'),actors:String(value('Actors') || '').split(',').map(name=>name.trim()).filter(Boolean) } };
}
export function queueEvaluation(draft, metadata) {
  if(!metadata?.imdbID) throw new Error('Сначала выбери фильм или сериал из поиска');
  const existing=loadLibrary().find(movie=>movie.omdb?.imdbID===metadata.imdbID);
  if(existing){
    const series=['series','tv-series'].includes(metadata.type);
    const order=existing.queueOrder || Math.max(0,...loadLibrary().filter(movie=>movie.status==='wish' && ['series','tv-series'].includes(movie.omdb?.type)===series).map(movie=>Number(movie.queueOrder)||0))+1;
    return updateMovie(existing.id,{status:'wish',queueOrder:order});
  }
  return saveEvaluation({draft:{...draft,status:'wish'},metadata,scores:{},editingId:null}).movie;
}

export function saveEvaluation({ draft, scores, metadata, editingId }) {
  const name = String(draft.name || '').trim();
  if(!name) throw new Error('Впиши название');
  const library = loadLibrary();
  const existing = editingId ? library.find(movie => movie.id === editingId) : null;
  const status = existing && draft.status === 'wish' ? 'watched' : draft.status || 'watched';
  const year = draft.year === '' || draft.year == null ? null : Number(draft.year);
  const tags = [...new Map(String(draft.tags || '').split(',').map(tag=>tag.trim()).filter(Boolean).map(tag=>[tag.toLocaleLowerCase(),tag])).values()];
  const kind = value => ['series','tv-series'].includes(value?.type) ? 'series' : 'movie';
  const queueOrder = status === 'wish' ? Math.max(0,...library.filter(movie=>movie.status==='wish' && kind(movie.omdb)===kind(metadata)).map(movie=>Number(movie.queueOrder)||0))+1 : null;
  const patch = { name, director:String(draft.director || '').trim(), year:Number.isFinite(year) && year !== null ? Math.max(1888,Math.min(2100,year)) : null, status, tags, notes:String(draft.notes || '').trim(), scores:Object.fromEntries(['overall','engage','emotions'].map(key=>[key,Math.max(0,Math.min(10,Number(scores[key])||0))])), queueOrder };
  if(metadata) patch.omdb = {...metadata};
  if(existing) return { movie:updateMovie(existing.id,patch), edited:true };
  const movie = { ...patch, id:crypto.randomUUID(), createdAt:Date.now(), favorite:false, omdb:metadata ? {...metadata} : null };
  addMovie(movie);
  return {movie,edited:false};
}

export function createEvaluationActions({ getDraft, onReset, onChanged, toast, navigate, onInvalid }) {
  function save() {
    let result;
    try { result = saveEvaluation(getDraft()); }
    catch (error) { toast(error.message); onInvalid?.(); return; }
    const { movie, edited } = result;
    toast(edited ? 'Оценка сохранена' : movie.status === 'wish' ? 'Добавлено в очередь' : 'Добавлено в оценённые', movie.name);
    onReset();
    onChanged();
    navigate(movie.status === 'wish' ? 'wish' : 'rated', { openId: movie.id });
    return movie;
  }
  function queue() {
    let movie;
    try {
      const { draft, metadata } = getDraft();
      movie = queueEvaluation(draft, metadata);
    } catch (error) { toast(error.message); return; }
    toast('Добавлено в очередь', movie.name);
    onChanged();
    navigate('wish', { openId: movie.id });
    return movie;
  }
  return { save, queue };
}

export function createEvaluationSearch({ onResults, onStatus, onSelected }) {
  let generation = 0;
  const search = createOmdbSearch({ request: omdbRequest, onResults, onStatus });
  async function select(id) {
    search.cancel();
    const version = ++generation;
    onStatus('Загружаю детали…');
    try {
      const data = await omdbRequest({ i: id, plot: 'short' });
      if (version !== generation) return;
      if (data.Response === 'False') {
        onStatus(data.Error || 'Не удалось получить детали.', true);
        return;
      }
      onSelected(fromOmdb(data));
      onStatus('Готово: данные подставлены. Теперь поставь оценки и нажми “Добавить”.');
    } catch {
      if (version === generation) onStatus('Ошибка при загрузке деталей из OMDb.', true);
    }
  }
  function cancel() { generation++; search.cancel(); }
  return {
    select,
    cancel,
    search(query) { generation++; return search.search(query); },
    schedule(query) { generation++; search.schedule(query); },
  };
}

let evaluationView = null;
const evaluationListeners = new Set();

export function getEvaluationView() { return evaluationView; }
export function subscribeEvaluationView(listener) {
  evaluationListeners.add(listener);
  return () => evaluationListeners.delete(listener);
}
export function publishEvaluationView(next) {
  evaluationView = next;
  evaluationListeners.forEach(listener => listener());
}
export function createEvaluationState() {
  return {
    draft: createEvaluationDraft(),
    scores: { overall: 0, engage: 0, emotions: 0 },
    metadata: null, editingId: null, results: [], revision: 0, message: '',
  };
}
export function resetEvaluationState(state) {
  const revision = state.revision;
  Object.assign(state, createEvaluationState(), { revision });
}
export function prepareEvaluation(state, selection) {
  resetEvaluationState(state);
  Object.assign(state.draft, selection.draft);
  state.metadata = selection.metadata;
  state.editingId = selection.editingId || null;
  if (selection.scores) Object.assign(state.scores, selection.scores);
  state.message = state.editingId ? 'Редактирование оценки' : '';
}
export function prepareCatalogEvaluation(state, movie, type) {
  prepareEvaluation(state, fromTmdb(movie, type));
}
export function prepareMovieEvaluation(state, movie) {
  prepareEvaluation(state, evaluationFromMovie(movie));
}

let openRating;
let applyCatalogMovie;
export function configureRatingNavigation(action) { openRating = action; }
export function configureCatalogRating(action) { applyCatalogMovie = action; }
export function requestCatalogRating(movie, type, action) {
  if (!applyCatalogMovie) throw new Error('Форма оценки ещё загружается');
  return applyCatalogMovie(movie, type, action);
}
export function requestMovieRating(movie) {
  if (!openRating) throw new Error('Форма оценки ещё загружается');
  return openRating(movie);
}
