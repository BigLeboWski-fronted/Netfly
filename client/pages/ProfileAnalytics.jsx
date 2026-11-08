import React, { useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { loadLibrary, subscribeLibrary } from '../state/library.js';
import { getProfileSnapshot, subscribeProfile, getProgressSnapshot, subscribeProgress, getEpisodeCache, subscribeEpisodeCache } from '../state/profile.js';
import { computeNowProgress, computeStreak, sumMinutesLast7Days } from '../state/seriesSelectors.js';
import { profileData } from '../state/profileSelectors.js';
import { getTopGenres } from '../state/genres.js';
import { ProfileTiles, ProfileScores, ProfileDeepStats, ProfileGenres, ProfileMovieList, ProfileFavorite, ProfileTagline, ProfileWeek } from './Profile.jsx';

export function ProfileAnalytics({ router, onPatch, toast, formatMinutes }) {
  const movies=useSyncExternalStore(subscribeLibrary,loadLibrary);
  const profile=useSyncExternalStore(subscribeProfile,getProfileSnapshot);
  const progressState=useSyncExternalStore(subscribeProgress,getProgressSnapshot);
  const cache=useSyncExternalStore(subscribeEpisodeCache,getEpisodeCache);
  const week=sumMinutesLast7Days(progressState,cache), progress=computeNowProgress(progressState,cache);
  const data=profileData(movies);
  const portal=(id,element)=>createPortal(element,document.getElementById(id),id);
  const open=id=>router.navigate('rated',{openId:id});
  const people=raw=>String(raw || '').split(',').map(value=>value.trim()).filter(Boolean);
  const favorite=(kind)=>{
    const person=kind==='actor'||kind==='director', actor=kind==='actor', series=kind==='series';
    const key=person?(actor?'favActorName':'favDirectorName'):(series?'favSeriesId':'favMovieId');
    const name=profile[key] || '';
    const names=person?[...new Set(data.rated.flatMap(movie=>actor?(movie.omdb?.actors || []):people(movie.director)))].sort((a,b)=>a.localeCompare(b,'ru')):[];
    const candidates=person?names.map(name=>({id:name,name})):data.rated.filter(movie=>['series','tv-series'].includes(movie.omdb?.type)===series);
    const films=person?data.rated.filter(movie=>(actor?(movie.omdb?.actors || []):people(movie.director)).some(value=>value.toLocaleLowerCase()===name.toLocaleLowerCase())):[];
    return <ProfileFavorite title={{actor:'Любимый актёр',director:'Любимый режиссёр',series:'Любимый сериал',movie:'Любимый фильм'}[kind]} people={person} name={person?name:null} movie={person?null:data.rated.find(movie=>movie.id===name)} candidates={candidates} films={films} onChoose={value=>onPatch({[key]:value})} onClear={()=>onPatch({[key]:person?'':null})} onOpen={open}/>;
  };
  function toggle(name){
    const selected=[...(profile.manualGenres || [])];
    const index=selected.indexOf(name);
    if(index>=0) selected.splice(index,1);
    else {if(selected.length>=2){toast('Можно выбрать максимум 2 жанра');return;}selected.push(name);}
    onPatch({manualGenres:selected});
  }
  return <>
    {portal('profileSubtitle',profile.tagline?.trim() || 'Твоя личная библиотека фильмов и сериалов')}
    {portal('profileTaglineRoot',<ProfileTagline value={profile.tagline} onChange={value=>onPatch({tagline:value})}/>)}
    {portal('profileWatchingWeek',<ProfileWeek week={week} time={formatMinutes(week.minutes)} streak={progressState.streakOn?computeStreak(progressState,cache)+' дн.':'выкл.'} progress={progress.total?`${progress.watched}/${progress.total} (${progress.pct || 0}%)`:progress.watched} goal={progressState.goalEps}/>)}
    {['movie','series','director','actor'].map(kind=>portal({movie:'favMovieCard',series:'favSeriesCard',director:'favDirectorCard',actor:'favActorCard'}[kind],favorite(kind)))}
    {portal('profileTiles',<ProfileTiles tiles={data.tiles}/>)}
    {portal('profileScores',<ProfileScores {...data.scores}/>)}
    {portal('profileDeepStats',<ProfileDeepStats movies={data.rated} formatMinutes={formatMinutes}/>)}
    {portal('profileGenreChips',<ProfileGenres genres={getTopGenres(movies,5).map(item=>item.name)}/>)}
    {portal('profileManualGenreChips',<ProfileGenres genres={data.allGenres} selected={profile.manualGenres} onToggle={toggle}/>)}
    {portal('bestList',<ProfileMovieList movies={data.best} onOpen={id=>router.navigate('rated',{openId:id})}/>)}
    {portal('recentRatedList',<ProfileMovieList movies={data.recent} onOpen={id=>router.navigate('rated',{openId:id})}/>)}
  </>;
}
