import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.jsx';
import { ConnectedSeries } from './pages/ConnectedSeries.jsx';
import { ProfileAnalytics } from './pages/ProfileAnalytics.jsx';
import { Confirmation } from './components/Confirmation.jsx';
import { ProfilePage, SettingsPage, Topbar, NowPage } from './components/PageShells.jsx';
import { RouterBrand, RouterNavigation } from './components/Navigation.jsx';
import { HomePage, ConnectedDashboard, ConnectedRecent } from './components/Home.jsx';
import './styles/components.css';
import { RoutedSearch, CatalogRoute } from './pages/CatalogRoutes.jsx';
import { RatedRoute, WishRoute } from './pages/LibraryRoutes.jsx';
import { request } from './api/tmdb.js';
import { accountRequest } from './api/account.js';
import { createSync } from './state/sync.js';
import { createAccountDataLoader } from './state/accountData.js';
import { createSeriesLoader } from './state/seriesLoader.js';
import { createOmdbSearch } from './state/omdbSearch.js';
import { createLibraryActions } from './state/libraryActions.js';
import { createEvaluationDraft, saveEvaluation, fromTmdb, fromOmdb, queueEvaluation } from './state/evaluation.js';
import { createRouter } from './state/router.js';
import * as profileStorage from './state/profile.js';
import * as session from './state/session.js';
import { profileData } from './state/profileSelectors.js';
import { getTopGenres } from './state/genres.js';
import * as seriesSelectors from './state/seriesSelectors.js';
import * as activeSeries from './state/activeSeries.js';
import { Evaluate } from './pages/Evaluate.jsx';
import { AuthScreen } from './pages/Auth.jsx';
import { Settings } from './pages/Settings.jsx';
import { AccountUsername, AccountCredentials } from './pages/Account.jsx';
import { AvatarEditor } from './components/AvatarEditor.jsx';
import { flushSync } from 'react-dom';
import { installLibraryBridge } from './state/library.js';

const views = new Map();
const appHost = document.getElementById('appReactRoot');
const appRoot = createRoot(appHost);
const router = createRouter(window);
let confirmationQueue = Promise.resolve();
function confirmAction(props) {
  const result = confirmationQueue.then(() => new Promise(resolve => {
    render('confirmationReactRoot', <Confirmation {...props} onResolve={value => { render('confirmationReactRoot', null); resolve(value); }} />);
  }));
  confirmationQueue = result.catch(() => false);
  return result;
}
installLibraryBridge(window);
function render(id, content) {
  const host = document.getElementById(id);
  if (!host) throw new Error(`React mount point missing: ${id}`);
  for (const [key, view] of views) if (!view.host.isConnected) views.delete(key);
  views.set(id, { host, content });
  appRoot.render(<App views={new Map(views)} router={router} />);
}

window.NetflyUI = {
  connectedSeries(props) { render('connectedSeriesRoot', <ConnectedSeries {...props} router={router} />); },
  createAccountDataLoader,
  accountRequest,
  session,
  profileAnalytics(props) { render('profileAnalyticsRoot', <ProfileAnalytics {...props} router={router} />); },
  topGenres: getTopGenres,
  profileData,
  activeSeries,
  createSeriesLoader,
  seriesSelectors,
  createOmdbSearch,
  evaluation: { fromTmdb, fromOmdb, queueEvaluation },
  saveEvaluation,
  confirm: confirmAction,
  libraryPages(dependencies) {
    const actions = createLibraryActions({ ...dependencies, router, confirm: confirmAction });
    render('ratedRoot', <RatedRoute {...actions.rated} router={router} />);
    render('wishRoot', <WishRoute {...actions.wish} router={router} />);
  },
  catalogActions(onAction) { render('moviePageContent', <CatalogRoute router={router} onAction={onAction} />); },
  createEvaluationDraft,
  router,
  profileStorage,
  createSync,
  evaluate(props) { render('evaluateReactRoot', <Evaluate {...props} />); },
  auth(props) { render('authScreen', <AuthScreen {...props} />); },
  settings(props) { render('settingsReactRoot', <Settings {...props} />); },
  accountCredentials(props) { render('accountReactRoot', props ? <AccountCredentials key={props.mode} {...props} /> : null); },
  accountUsername(props) { render('accountReactRoot', props ? <AccountUsername {...props} /> : null); },
  avatarEditor(props) { render('avatarEditorRoot', <AvatarEditor {...props} />); },
  request,
  home(props) { render('homeDashboard', <ConnectedDashboard {...props} router={router} />); render('recentWrap', <ConnectedRecent router={router} />); },
};

// Mount page-owned hosts before the temporary inline controller reads them.
flushSync(() => {
  render('view-home', <HomePage />);
  render('view-profile', <ProfilePage />);
  render('view-settings', <SettingsPage />);
  render('topbarReactRoot', <Topbar />);
  render('nowPageReactRoot', <NowPage />);
});
flushSync(() => {
  render('brandRoot', <RouterBrand router={router} />);
  render('nav', <RouterNavigation router={router} />);
  render('mobileNav', <RouterNavigation router={router} />);
  render('searchRoot', <RoutedSearch router={router} />);
});
