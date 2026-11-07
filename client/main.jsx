import React from 'react';
import { createRoot } from 'react-dom/client';
import { Brand, Navigation } from './components/Navigation.jsx';
import { HomeDashboard, RecentMovies } from './components/Home.jsx';
import './styles/components.css';
import { Search } from './pages/Search.jsx';
import { Movie } from './pages/Movie.jsx';
import { Person } from './pages/Person.jsx';
import { RatedPage } from './pages/Rated.jsx';
import { WishPage } from './pages/Wish.jsx';
import { request } from './api/tmdb.js';
import { Evaluate } from './pages/Evaluate.jsx';
import { Login } from './pages/Auth.jsx';
import { PasswordRecovery } from './pages/PasswordRecovery.jsx';
import { Register } from './pages/Register.jsx';
import { Settings } from './pages/Settings.jsx';
import { AccountUsername, AccountCredentials } from './pages/Account.jsx';
import { AvatarEditor } from './components/AvatarEditor.jsx';
import { ProfileTiles, ProfileWeek, ProfileScores, ProfileDeepStats, ProfileGenres, ProfileFavorite, ProfileMovieList, ProfileTagline } from './pages/Profile.jsx';
import { SeriesEpisodes, SeriesCalendar, SeriesProgress, SeriesHomeWidget, SeriesControls } from './pages/Series.jsx';
import { flushSync } from 'react-dom';
import { installLibraryBridge, subscribeLibrary } from './state/library.js';

// Temporary boundary between React-owned containers and the legacy application.
// One root per container, reused on every data refresh and navigation.
const roots = new Map();
installLibraryBridge(window);
let searchProps = null;
let ratedProps = null;
let wishProps = null;

// Keep React list pages in sync when a legacy action writes to the shared
// library. The legacy layer remains responsible for navigation and callbacks;
// this subscription only refreshes the data prop.
subscribeLibrary(movies => {
  if (ratedProps) {
    ratedProps = { ...ratedProps, movies };
    render('ratedRoot', <RatedPage {...ratedProps} />);
  }
  if (wishProps) {
    wishProps = { ...wishProps, movies };
    render('wishRoot', <WishPage {...wishProps} />);
  }
});
function render(id, content) {
  const host = document.getElementById(id);
  if (!host) throw new Error(`React mount point missing: ${id}`);
  if (roots.has(id) && roots.get(id)._netflyHost !== host) {
    roots.get(id).unmount();
    roots.delete(id);
  }
  if (!roots.has(id)) roots.set(id, createRoot(host));
  roots.get(id)._netflyHost = host;
  roots.get(id).render(content);
}

window.NetflyUI = {
  evaluate(props) { render('evaluateReactRoot', <Evaluate {...props} />); },
  recovery(props) { render('recoveryReactRoot', <PasswordRecovery {...props} />); },
  registration(props) { render('registerReactRoot', <Register {...props} />); },
  login(props) { render('loginReactRoot', <Login {...props} />); },
  settings(props) { render('settingsReactRoot', <Settings {...props} />); },
  accountCredentials(props) { render('accountReactRoot', props ? <AccountCredentials key={props.mode} {...props} /> : null); },
  accountUsername(props) { render('accountReactRoot', props ? <AccountUsername {...props} /> : null); },
  avatarEditor(props) { render('avatarEditorRoot', <AvatarEditor {...props} />); },
  profileLists(props) { render('bestList', <ProfileMovieList movies={props.best} onOpen={props.onOpen} />); render('recentRatedList', <ProfileMovieList movies={props.recent} onOpen={props.onOpen} />); },
  profileTagline(props) { render('profileTaglineRoot', <ProfileTagline {...props} />); },
  profileFavorite(id, props) { render(id, <ProfileFavorite {...props} />); },
  profileDeep(props) { render('profileDeepStats', <ProfileDeepStats {...props} />); },
  profileGenres(props) { render('profileGenreChips', <ProfileGenres genres={props.top} />); render('profileManualGenreChips', <ProfileGenres genres={props.all} selected={props.selected} onToggle={props.onToggle} />); },
  profileTiles(props) { render('profileTiles', <ProfileTiles {...props} />); },
  profileWeek(props) { render('profileWatchingWeek', <ProfileWeek {...props} />); },
  profileScores(props) { render('profileScores', <ProfileScores {...props} />); },
  seriesControls(props) { render('seriesControlsRoot', <SeriesControls {...props} />); },
  seriesHome(props) { render('nowWidgetHome', <SeriesHomeWidget {...props} />); },
  seriesProgress(props) { flushSync(() => render('nowCard', <SeriesProgress {...props} />)); },
  episodes(props) { render('nowEpisodes', <SeriesEpisodes {...props} />); },
  calendar(props) { render('seriesCalendar', props ? <SeriesCalendar {...props} /> : null); },
  request,
  route(view) {
    if (searchProps) render('searchRoot', <Search {...searchProps} active={view === 'search'} />);
    if (view !== 'movie' && view !== 'person' && roots.has('moviePageContent')) render('moviePageContent', null);
  },
  search(props) {
    searchProps = props;
    render('searchRoot', <Search {...props} active />);
  },
  movie(props) { render('moviePageContent', <Movie key={props.type + ':' + props.id} {...props} />); },
  person(props) { render('moviePageContent', <Person key={'person:' + props.id} {...props} />); },
  rated(props) {
    ratedProps = props;
    render('ratedRoot', <RatedPage {...props} />);
  },
  ratedOpen(id) {
    if (ratedProps) render('ratedRoot', <RatedPage {...ratedProps} openId={id} />);
  },
  wish(props) {
    wishProps = props;
    render('wishRoot', <WishPage {...props} />);
  },
  wishOpen(id) {
    if (wishProps) render('wishRoot', <WishPage {...wishProps} openId={id} />);
  },
  navigation(props) {
    render('brandRoot', <Brand onNavigate={props.onNavigate} />);
    render('nav', <Navigation {...props} />);
    render('mobileNav', <Navigation {...props} />);
  },
  dashboard(props) { render('homeDashboard', <HomeDashboard {...props} />); },
  recent(props) { render('recentWrap', <RecentMovies {...props} />); },
};
