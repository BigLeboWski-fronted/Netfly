import React, { useSyncExternalStore } from 'react';

const tabs = [
  {id:'home',label:'Главная'}, {id:'search',label:'Поиск'},
  {id:'rated',label:'Оценённые'}, {id:'wish',label:'Буду смотреть'},
  {id:'now',label:'Смотрю сейчас'},
];
export function RouterNavigation({ router }) {
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  return <Navigation views={tabs} currentView={route.viewId} onNavigate={router.navigate} />;
}
export function RouterBrand({ router }) { return <Brand onNavigate={router.navigate} />; }

export function Brand({ onNavigate }) {
  return <a href="/" className="brandMini" onClick={event => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    onNavigate('home');
  }}><img src="/icon.svg" className="logoMark" aria-hidden="true" alt="" />Netfly</a>;
}

export function Navigation({ views, currentView, onNavigate }) {
  return views.map(view => <button key={view.id} type="button"
    className={'navBtn' + (currentView === view.id ? ' active' : '')}
    aria-current={currentView === view.id ? 'page' : undefined}
    onClick={() => onNavigate(view.id)}>{view.label}</button>);
}
