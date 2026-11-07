import React from 'react';

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
