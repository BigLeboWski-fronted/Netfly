import React, { createContext, useLayoutEffect, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { getSessionSnapshot, subscribeSession } from './state/session.js';
import { Toasts } from './components/Toasts.jsx';
import { Confetti } from './components/Confetti.jsx';

// All migrated views share one React tree. Portals keep existing page hosts
// available until the remaining HTML shell is migrated.
export const RouteContext = createContext(null);

function PageVisibility({ route }) {
  useLayoutEffect(() => {
    const selected = route.viewId === 'person' ? 'movie' : route.viewId;
    const ids = ['home','evaluate','rated','search','movie','wish','now','profile','settings'];
    for(const id of ids) document.getElementById(`view-${id}`)?.classList.toggle('hidden', id !== selected);
    document.getElementById('view-wish-movies')?.classList.add('hidden');
    document.getElementById('view-wish-series')?.classList.add('hidden');
    document.getElementById('profileBtn')?.classList.toggle('active', selected === 'profile');
    document.getElementById('settingsBtn')?.classList.toggle('active', selected === 'settings');
    const page = document.getElementById(`view-${selected}`);
    if(page) { page.classList.remove('viewTransition'); void page.offsetWidth; page.classList.add('viewTransition'); }
  }, [route]);
  return null;
}

export function App({ views, router }) {
  const session=useSyncExternalStore(subscribeSession,getSessionSnapshot);
  useLayoutEffect(()=>{document.getElementById('authScreen')?.classList.toggle('hidden',!!session.user);},[session.user]);
  const route = useSyncExternalStore(router.subscribe, router.getSnapshot);
  return <RouteContext.Provider value={route}><Toasts /><Confetti /><PageVisibility route={route} />{Array.from(views, ([id, { host, content }]) =>
    createPortal(content, host, id)
  )}</RouteContext.Provider>;
}
