import { markEpisode, recordActivity, recordViewing, resetProgress, updateProgress } from './profile.js';

// Pure progress transitions shared by the React surface and the legacy bridge.
// Persistence remains injected so this module does not own synchronization.
export function createProgressActions({ getState, setState, save, now = () => Date.now() }) {
  const commit = patch => {
    const next = updateProgress(getState(), patch);
    setState(next);
    save(next);
    return next;
  };

  function patchProgress(patch) { return commit(patch); }

  function setEpisode(key, checked) {
    const current = getState();
    let next = markEpisode(current, key, checked);
    if (checked && !current.watched?.[key]) {
      const timestamp = now();
      const date = new Date(timestamp);
      const day = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
      next = recordActivity(next, day);
      next = recordViewing(next, { ts: timestamp, eps: 1, minutes: Number(next.runtimeMin || 0) || 0 });
    }
    setState(next);
    save(next);
    return next;
  }

  function clear() { return commit(resetProgress(getState())); }

  return { patchProgress, setEpisode, clear };
}
