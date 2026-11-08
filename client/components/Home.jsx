import React, { useSyncExternalStore } from 'react';
import { loadLibrary, subscribeLibrary } from '../state/library.js';
import { dashboardData, recentMovies } from '../state/home.js';
import { Poster } from './Poster.jsx';

export function ConnectedDashboard({ profile, nowState, router }) {
  const movies=useSyncExternalStore(subscribeLibrary,loadLibrary);
  return <HomeDashboard {...dashboardData(movies,profile,nowState)} onNavigate={router.navigate} />;
}
export function ConnectedRecent({ router }) {
  const movies=useSyncExternalStore(subscribeLibrary,loadLibrary);
  return <RecentMovies movies={recentMovies(movies)} onNavigate={router.navigate} />;
}

export function HomePage() {
  return <>
    <div className="homeCenter"><h1 className="homeTitle">Net<span className="red">fly</span></h1><div className="homeSub">Твой личный трекер фильмов и сериалов: оценивай, сохраняй «буду смотреть», собирай избранное и находи новые идеи.</div></div>
    <div id="homeDashboard" className="homeDashboard" />
    <div className="card"><div className="sectionTitle">Последние оценённые</div><div id="recentWrap" /><div id="nowWidgetHome" /></div>
  </>;
}

export function HomeDashboard({ cards, onNavigate }) {
  return cards.map(card => {
    const content = <>
      <div className="homeDashIcon" aria-hidden="true">{card.icon}</div>
      <div className="homeDashLabel">{card.label}</div>
      <div className="homeDashValue">{card.value}</div>
      <div className="homeDashMeta">{card.meta}</div>
    </>;
    return card.action
      ? <button key={card.label} type="button" className="homeDashCard homeDashButton"
          onClick={() => onNavigate(card.action)}>{content}</button>
      : <div key={card.label} className="homeDashCard static">{content}</div>;
  });
}

export function RecentMovies({ movies, onNavigate }) {
  if (!movies.length) return <div className="emptyNote">Пока нет оценённых — перейди в «Поиск» и добавь первый фильм.</div>;
  return <div className="recentGrid">{movies.map(movie =>
    <button key={movie.id} type="button" className="recentCard recentMovieButton"
      onClick={() => onNavigate('rated')}>
      <Poster src={movie.posterUrl} title={movie.name} />
      <div className="recentTxt">
        <p className="recentName">{movie.name}</p>
        <div className="scoreBadge">{movie.score}</div>
      </div>
    </button>
  )}</div>;
}
