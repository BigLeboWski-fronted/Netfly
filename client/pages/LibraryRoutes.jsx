import React, { useSyncExternalStore } from 'react';
import { loadLibrary, subscribeLibrary } from '../state/library.js';
import { RatedPage } from './Rated.jsx';
import { WishPage } from './Wish.jsx';

export function RatedRoute({ router, ...actions }) {
  const movies = useSyncExternalStore(subscribeLibrary, loadLibrary);
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  return <RatedPage {...actions} movies={movies} openId={route.viewId === 'rated' ? route.opts.openId : null} />;
}
export function WishRoute({ router, ...actions }) {
  const movies = useSyncExternalStore(subscribeLibrary, loadLibrary);
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  return <WishPage {...actions} movies={movies} openId={route.viewId === 'wish' ? route.opts.openId : null} />;
}
