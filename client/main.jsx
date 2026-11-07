import React from 'react';
import { createRoot } from 'react-dom/client';
import { Brand, Navigation } from './components/Navigation.jsx';
import { HomeDashboard, RecentMovies } from './components/Home.jsx';
import './styles/components.css';
import { Search } from './pages/Search.jsx';
import { Movie } from './pages/Movie.jsx';
import { Person } from './pages/Person.jsx';
import { request } from './api/tmdb.js';

// Temporary boundary between React-owned containers and the legacy application.
// One root per container, reused on every data refresh and navigation.
const roots = new Map();
let searchProps = null;
function render(id, content) {
  const host = document.getElementById(id);
  if (!host) throw new Error(`React mount point missing: ${id}`);
  if (!roots.has(id)) roots.set(id, createRoot(host));
  roots.get(id).render(content);
}

window.NetflyUI = {
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
  navigation(props) {
    render('brandRoot', <Brand onNavigate={props.onNavigate} />);
    render('nav', <Navigation {...props} />);
    render('mobileNav', <Navigation {...props} />);
  },
  dashboard(props) { render('homeDashboard', <HomeDashboard {...props} />); },
  recent(props) { render('recentWrap', <RecentMovies {...props} />); },
};
