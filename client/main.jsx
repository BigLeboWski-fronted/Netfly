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
import './styles/appearance.css';
import { RoutedSearch, CatalogRoute } from './pages/CatalogRoutes.jsx';
import { RatedRoute, WishRoute } from './pages/LibraryRoutes.jsx';
import { createLibraryActions } from './state/libraryActions.js';
import { createRouter } from './state/router.js';
import * as profileStorage from './state/profile.js';
import { ConnectedEvaluate } from './pages/ConnectedEvaluate.jsx';
import { ConnectedAuthScreen } from './pages/Auth.jsx';
import { ConnectedSettings } from './pages/Settings.jsx';
import { loadAppearance, applyAppearance } from './state/appearance.js';
import { ConnectedAvatarEditor } from './components/AvatarEditor.jsx';
import { flushSync } from 'react-dom';
import * as library from './state/library.js';
import { formatMinutes } from './state/format.js';
import { configureRatingNavigation, requestMovieRating, configureCatalogRating, requestCatalogRating } from './state/ratingNavigation.js';
import { createEvaluationController } from './state/evaluationController.js';
import { createAppRuntime } from './state/appRuntime.js';
import { toast } from './components/Toasts.jsx';

const views = new Map();
const appHost = document.getElementById('appReactRoot');
const appRoot = createRoot(appHost);
const router = createRouter(window);
const evaluationController = createEvaluationController(router);
const appRuntime = createAppRuntime({ router, evaluation: evaluationController });
configureRatingNavigation(evaluationController.rate);
configureCatalogRating(evaluationController.catalog);
applyAppearance(loadAppearance());
let confirmationQueue = Promise.resolve();
function confirmAction(props) {
  const result = confirmationQueue.then(() => new Promise(resolve => {
    render('confirmationReactRoot', <Confirmation {...props} onResolve={value => { render('confirmationReactRoot', null); resolve(value); }} />);
  }));
  confirmationQueue = result.catch(() => false);
  return result;
}
function render(id, content) {
  const host = document.getElementById(id);
  if (!host) throw new Error(`React mount point missing: ${id}`);
  for (const [key, view] of views) if (!view.host.isConnected) views.delete(key);
  views.set(id, { host, content });
  appRoot.render(<App views={new Map(views)} router={router} />);
}

// Explicitly enabled only by the isolated integration harness.
if (window.__NETFLY_TEST__) window.__netflyTest = { library, profileStorage, evaluationController, router };

// Create page shells before mounting their nested portals.
flushSync(() => {
  render('view-home', <HomePage />);
  render('view-profile', <ProfilePage />);
  render('view-settings', <SettingsPage />);
  render('topbarReactRoot', <Topbar router={router} />);
  render('nowPageReactRoot', <NowPage />);
});
flushSync(() => {
  render('brandRoot', <RouterBrand router={router} />);
  render('nav', <RouterNavigation router={router} />);
  render('mobileNav', <RouterNavigation router={router} />);
  render('searchRoot', <RoutedSearch router={router} />);
  render('settingsReactRoot', <ConnectedSettings />);
  render('avatarEditorRoot', <ConnectedAvatarEditor />);
  render('homeDashboard', <ConnectedDashboard router={router} />);
  render('recentWrap', <ConnectedRecent router={router} />);
  render('profileAnalyticsRoot', <ProfileAnalytics router={router} />);
  render('authScreen', <ConnectedAuthScreen />);
  render('evaluateReactRoot', <ConnectedEvaluate />);
  render('moviePageContent', <CatalogRoute router={router} onAction={requestCatalogRating} />);
  const libraryActions = createLibraryActions({ router, toast, onRate: requestMovieRating, confirm: confirmAction });
  render('ratedRoot', <RatedRoute {...libraryActions.rated} router={router} />);
  render('wishRoot', <WishRoute {...libraryActions.wish} router={router} />);
  render('connectedSeriesRoot', <ConnectedSeries {...appRuntime.series} formatMinutes={formatMinutes} router={router} />);
});
appRuntime.account.restore();
router.restore();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}
