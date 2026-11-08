import React, { useSyncExternalStore } from 'react';
import { Search } from './Search.jsx';
import { Movie } from './Movie.jsx';
import { Person } from './Person.jsx';
import { loadLibrary, subscribeLibrary } from '../state/library.js';

export function RoutedSearch({ router }) {
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  return <Search active={route.viewId === 'search'} onNavigate={router.navigate} />;
}

export function CatalogRoute({ router, onAction }) {
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  const movies = useSyncExternalStore(subscribeLibrary, loadLibrary);
  if(route.viewId === 'person') return <Person key={`person:${route.opts.personId}`} id={route.opts.personId} onNavigate={router.navigate} />;
  if(route.viewId !== 'movie') return null;
  const type = route.opts.type === 'tv' ? 'tv' : 'movie';
  const library = movies.map(movie => ({ ...movie, formattedScore: (['overall','engage','emotions'].reduce((sum,key) => sum + Math.max(0,Math.min(10,Number(movie.scores?.[key] || 0))),0)/3).toFixed(1) }));
  return <Movie key={`${type}:${route.opts.tmdbId}`} id={route.opts.tmdbId} type={type} library={library} onNavigate={router.navigate} onAction={onAction} />;
}
