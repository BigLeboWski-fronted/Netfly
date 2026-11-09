import * as storage from './profile.js';
import { loadLibrary } from './library.js';
import * as session from './session.js';
import { accountRequest } from '../api/account.js';
import { createAccountSync } from './accountSync.js';
import { createAccountSession } from './accountSession.js';
import { createProgressActions } from './progressActions.js';
import { createSeriesEpisodes } from './seriesEpisodes.js';
import { createActiveSeriesActions } from './activeSeriesActions.js';
import { parseRuntimeMinutes } from './runtime.js';
import { toast } from '../components/Toasts.jsx';
import { launchConfetti } from '../components/Confetti.jsx';

export function createAppRuntime({ router, evaluation }) {
  let updatedAt = null;
  const sync = createAccountSync({
    request: accountRequest, getSession: session.getSessionSnapshot,
    getSnapshot: () => ({ movies: loadLibrary(), profile: storage.getProfileSnapshot(), now_state: storage.getProgressSnapshot(), omdb_ep_cache: storage.getEpisodeCache(), updated_at: updatedAt }),
    onLoaded: snapshot => { updatedAt = snapshot.updatedAt || null; }, onStatus: session.setSyncStatus,
    onSaved: (snapshot, result) => {
      updatedAt = result?.updated_at || updatedAt;
      if (JSON.stringify(loadLibrary()) === JSON.stringify(snapshot.movies)) localStorage.removeItem('netfly_library_pending');
    },
  });
  sync.bindLibraryChanges();
  sync.bindProfileChanges();
  storage.subscribeProgress(() => sync.schedule());
  const progress = createProgressActions({ getState: storage.getProgressSnapshot, setState: () => {}, save: storage.saveNowState });
  const episodes = createSeriesEpisodes({ getProgress: storage.getProgressSnapshot, patchProgress: progress.patchProgress, parseRuntime: parseRuntimeMinutes, onCache: () => {} });
  let pendingState;
  const active = createActiveSeriesActions({
    getState: storage.getProgressSnapshot, setState: state => { pendingState = state; },
    save: () => storage.saveNowState(pendingState), parseRuntime: parseRuntimeMinutes, toast,
    onRate: evaluation.rate, onDraft: evaluation.draft,
  });
  const account = createAccountSession({ sync });
  return {
    account, sync,
    series: {
      loadEpisodes: episodes.load, onMark: progress.setEpisode, onPatch: progress.patchProgress,
      onReset: progress.clear, onRemove: active.clear, onRate: active.rate,
      onPick: id => { active.select(loadLibrary().find(movie => movie.id === id)); router.navigate('now'); },
      onCompleted: id => { progress.patchProgress({ finishPromptedFor: id, finishDismissedFor: null }); launchConfetti(); },
    },
  };
}
