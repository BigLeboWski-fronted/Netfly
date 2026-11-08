import { createAccountDataLoader } from './accountData.js';
import { createSync } from './sync.js';
import { subscribeProfile, getProfileSnapshot } from './profile.js';

// Coordinates account hydration and debounced persistence without depending on
// the legacy page controller's global variables.
export function createAccountSync({ request, getSession, getSnapshot, onApplying, onLoaded, onStatus, onSaved, onLibraryChange, onProfileChange }) {
  let loading = false;
  const loader = createAccountDataLoader({
    request,
    onApplying: value => { loading = value; onApplying?.(value); },
    onLoaded,
    onPending: () => sync.schedule(),
  });
  const sync = createSync({
    request,
    getSnapshot,
    isAuthenticated: () => !!getSession()?.user,
    onStatus,
    onSaved,
  });
  return {
    loader,
    sync,
    isLoading: () => loading,
    load: () => loader.load(),
    schedule: () => sync.schedule(),
    flush: () => sync.flush(),
    cancel: () => { loader.cancel(); sync.cancel(); },
    bindLibraryChanges: (target = globalThis, storage = globalThis.localStorage) => {
      const listener = () => {
        onLibraryChange?.();
        if (loading) return;
        try { storage.setItem('netfly_library_pending', '1'); } catch {}
        sync.schedule();
      };
      target.addEventListener?.('netfly:library-change', listener);
      return () => target.removeEventListener?.('netfly:library-change', listener);
    },
    wrapSave: save => (...args) => {
      const result = save(...args);
      sync.schedule();
      return result;
    },
    bindProfileChanges: () => subscribeProfile(() => {
      onProfileChange?.(getProfileSnapshot());
      if (!loading) sync.schedule();
    }),
  };
}
