import React, { useEffect, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { loadLibrary, subscribeLibrary } from '../state/library.js';
import { getProgressSnapshot, subscribeProgress, getEpisodeCache, subscribeEpisodeCache } from '../state/profile.js';
import { computeNowProgress, getNextUnwatched, computeWeeksWatching, computeStreak, sumMinutesLast7Days } from '../state/seriesSelectors.js';
import { SeriesControls, SeriesProgress, SeriesEpisodes, SeriesHomeWidget, SeriesCalendar } from './Series.jsx';

export function ConnectedSeries({ router, onMark, onPatch, onReset, onPick, onRemove, onRate, onCompleted, loadEpisodes, formatMinutes }) {
  const state=useSyncExternalStore(subscribeProgress,getProgressSnapshot);
  const cache=useSyncExternalStore(subscribeEpisodeCache,getEpisodeCache);
  const movies=useSyncExternalStore(subscribeLibrary,loadLibrary);
  const route=useSyncExternalStore(router.subscribe,router.getSnapshot);
  const progress=computeNowProgress(state,cache), next=getNextUnwatched(state,cache);
  const entry=cache[state.imdbID], finished=!!state.imdbID && !!entry?.totalEpisodes && !next;
  useEffect(()=>{if(state.imdbID && route.viewId==='now') loadEpisodes();},[state.imdbID,route.viewId]);
  useEffect(()=>{if(finished && state.finishPromptedFor!==state.imdbID) onCompleted(state.imdbID);},[finished,state.imdbID,state.finishPromptedFor]);
  const markNext=()=>{if(next)onMark(`S${next.season}E${next.episode}`,true);};
  const source=movies.find(movie=>movie.id===state.sourceMovieId || movie.omdb?.imdbID===state.imdbID);
  const week=sumMinutesLast7Days(state,cache), stats=[];
  if(week.eps || week.minutes)stats.push(`За 7 дней: ${week.eps} серий / ${formatMinutes(week.minutes)}`);
  if(state.streakOn)stats.push(`Стрик: ${computeStreak(state,cache)} дн.`);
  if(state.goalEps>0)stats.push(`Цель недели: ${state.goalEps} серий`);
  const portal=(id,element)=>createPortal(element,document.getElementById(id),id);
  return <>
    {portal('nowWidgetHome',<SeriesHomeWidget state={state} progress={progress} next={next} weeks={computeWeeksWatching(state,cache)} onOpen={()=>router.navigate('now')} onNext={markNext}/>)}
    {portal('nowStatsTop',stats.join(' • '))}
    {portal('seriesCalendar',<SeriesCalendar imdbId={state.imdbID} tmdbId={source?.omdb?.tmdbId}/>)}
    {portal('seriesControlsRoot',<SeriesControls active={!!state.imdbID} next={next} finished={finished && state.finishDismissedFor!==state.imdbID} queue={movies.filter(movie=>movie.status==='wish' && ['series','tv-series'].includes(movie.omdb?.type))} onReveal={()=>{if(next)window.dispatchEvent(new CustomEvent('netfly:reveal-episode',{detail:next}));}} onPick={onPick} onRemove={onRemove} onRate={onRate} onDismiss={()=>onPatch({finishDismissedFor:state.imdbID})}/>)}
    {portal('nowCard',<SeriesProgress state={state} progress={progress} next={next} onNext={markNext} onSettings={onPatch} onReset={onReset}><SeriesEpisodes key={state.imdbID} seriesId={state.imdbID} seasons={entry?.seasons || {}} watched={state.watched} onToggle={onMark}/></SeriesProgress>)}
  </>;
}
