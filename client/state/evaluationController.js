import { createEvaluationState, publishEvaluationView, resetEvaluationState, prepareMovieEvaluation, prepareCatalogEvaluation, prepareEvaluation, createEvaluationActions, createEvaluationSearch } from './evaluation.js';
import { toast } from '../components/Toasts.jsx';

export function createEvaluationController(router) {
  const state = createEvaluationState();
  function publish() {
    publishEvaluationView({
      initial: { ...state.draft, scores: { ...state.scores }, editing: !!state.editingId },
      revision: ++state.revision, results: state.results, message: state.message,
      onChange(key, value) {
        if (key === 'scores') Object.assign(state.scores, value);
        else state.draft[key] = value;
        if (key === 'name') search.schedule(state.draft.name);
      },
      onSearch: () => search.search(state.draft.name.trim()),
      onSelect: async id => { dismiss(); await search.select(id); publish(); },
      onDismiss: dismiss, onSave: () => actions.save(), onWish: () => actions.queue(),
    });
  }
  function dismiss() { state.results = []; publish(); }
  const search = createEvaluationSearch({
    onResults: results => { state.results = results; publish(); },
    onStatus: (text, error) => { state.message = text ? (error ? 'Ошибка: ' : '') + text : ''; publish(); },
    onSelected: selected => {
      for (const [key, value] of Object.entries(selected.draft)) if (value != null) state.draft[key] = value;
      state.metadata = selected.metadata;
    },
  });
  const actions = createEvaluationActions({
    getDraft: () => ({ draft: state.draft, scores: state.scores, metadata: state.metadata, editingId: state.editingId }),
    onReset: () => { search.cancel(); resetEvaluationState(state); publish(); },
    onChanged: () => {},
    onInvalid: () => document.getElementById('evaluate-name')?.focus(),
    toast, navigate: router.navigate,
  });
  router.subscribe(route => { if (route.viewId !== 'evaluate') search.cancel(); });
  function open() { publish(); router.navigate('evaluate'); }
  publish();
  return {
    state,
    rate(movie) { if (!movie) return; search.cancel(); prepareMovieEvaluation(state, movie); open(); },
    catalog(movie, type, action) {
      search.cancel(); prepareCatalogEvaluation(state, movie, type);
      if (action === 'wish') actions.queue(); else open();
    },
    draft(draft, metadata) { search.cancel(); prepareEvaluation(state, { draft, metadata }); open(); },
  };
}
