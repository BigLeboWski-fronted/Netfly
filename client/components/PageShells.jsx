import React, { useSyncExternalStore } from 'react';
import { getSessionSnapshot, subscribeSession, logout } from '../state/session.js';
import { Avatar } from './Avatar.jsx';

export function Topbar() {
  const session=useSyncExternalStore(subscribeSession,getSessionSnapshot);
  return <><div className="topbar"><div className="topbarInner"><span id="brandRoot"/><div className="nav" id="nav"/><div className="profileWrap"><button className="profileBtn" id="profileBtn" type="button" title="Профиль" aria-label="Профиль"><Avatar size={18}/></button></div><div className="userBadge" id="userBadge" style={{display:session.user?'flex':'none'}}><div className={'syncDot '+session.syncStatus} id="syncDot" title="Синхронизация"/><span id="userBadgeName">{session.user}</span><button type="button" id="logoutBtn" onClick={logout} disabled={session.loggingOut}>{session.loggingOut?'Выходим…':'Выйти'}</button></div><button className="settingsBtn" id="settingsBtn" type="button" title="Настройки" aria-label="Настройки"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2"/></svg></button></div></div><nav className="mobileNav" id="mobileNav" aria-label="Навигация"/></>;
}

export function NowPage() {
  return <section className="card"><div className="listHeader"><div className="listTop"><h2>Смотрю сейчас</h2><div className="small" id="nowStatsTop"/></div><div id="seriesControlsRoot"/></div><section id="seriesCalendar" className="profileSection" aria-live="polite"/><div id="nowCard"/></section>;
}

export function SettingsPage() {
  return <div className="settingsView"><div className="settingsGroup"><div className="settingsRow"><div className="settingsRowLabel"><strong>Аватар</strong><span>Фото профиля</span></div><div style={{display:'flex',alignItems:'center',gap:10}}><div className="avatarCircle" id="settingsAvatar" style={{width:40,height:40,boxShadow:'none'}}><Avatar size={20}/></div><div id="avatarEditorRoot"/></div></div></div><div id="settingsReactRoot"/></div>;
}

export function ProfilePage() {
  return <section className="card profilePage"><div className="profileLayout"><div className="profileLeft">
    <div className="profileHero"><div className="avatarCircle" id="profileAvatar" aria-hidden="true"><Avatar/></div><div><h2 className="profileTitle">Мой профиль</h2><div className="profileSubtitle" id="profileSubtitle">Твоя личная библиотека фильмов и сериалов</div></div></div>
    <div id="profileAnalyticsRoot"/><div className="statTiles" id="profileTiles"/>
    <section className="profileSection"><div className="secHead"><h3>Мой вкус</h3><div className="small">Любимые жанры</div></div><div className="genreChips" id="profileGenreChips"/></section>
    <details className="profileFold"><summary>Настроить профиль</summary><div className="fieldRow"><div id="profileTaglineRoot"/><div className="small muted">Покажем её под заголовком профиля.</div></div><div style={{marginTop:10}}><div className="small">Любимые жанры вручную (до 2)</div><div className="genreChips" id="profileManualGenreChips"/><div className="small muted" style={{marginTop:6}}>Выбери из жанров, которые есть в твоей библиотеке.</div></div></details>
  </div><div className="profileRight">
    <details className="profileFold"><summary>Статистика и оценки</summary>{['profileScores','profileDeepStats','profileWatchingWeek'].map(id=><div className="profileSection" id={id} key={id}/>)}</details>
    <details className="profileFold"><summary>Любимые фильмы, актёры и режиссёры</summary><div className="favGrid" id="profileFavGrid">{['favMovieCard','favSeriesCard','favDirectorCard','favActorCard'].map(id=><div className="favCard" id={id} key={id}/>)}</div></details>
    <div className="twoCol">{[['bestList','Лучшие по оценке','Топ‑3'],['recentRatedList','Недавно оценённые','Последние 3']].map(([id,title,hint])=><section className="profileSection" key={id}><div className="secHead"><h3>{title}</h3><div className="small">{hint}</div></div><div className="miniList" id={id}/></section>)}</div>
  </div></div><datalist id="directorDatalist"/><datalist id="actorDatalist"/></section>;
}
