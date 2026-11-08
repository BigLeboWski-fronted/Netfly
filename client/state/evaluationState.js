import { createEvaluationDraft, fromTmdb, evaluationFromMovie } from './evaluation.js';

let view = null;
const listeners = new Set();
export function getEvaluationView() { return view; }
export function subscribeEvaluationView(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
export function publishEvaluationView(next) {
  view = next;
  listeners.forEach(listener => listener());
}

export function createEvaluationState() {
  return {
    draft: createEvaluationDraft(),
    scores: { overall: 0, engage: 0, emotions: 0 },
    metadata: null,
    editingId: null,
    results: [],
    revision: 0,
    message: '',
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
