const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { JSDOM, VirtualConsole } = require('jsdom');

// Runs the actual built React bundle and legacy scripts together. All API calls
// are mocked; no user account, local browser storage or database is touched.
async function test() {
  const html = fs.readFileSync('public/index.html', 'utf8');
  const errors = [];
  const console = new VirtualConsole();
  console.on('jsdomError', error => errors.push(error));
  console.on('error', (...args) => errors.push(args.join(' ')));
  const dom = new JSDOM(html, {
    url: 'http://localhost/', runScripts: 'outside-only',
    pretendToBeVisual: true, virtualConsole: console,
  });
  const { window } = dom;
  const context = dom.getInternalVMContext();
  const run = code => vm.runInContext(code, context);
  const settle = () => new Promise(resolve => setTimeout(resolve, 60));
  try {
    window.scrollTo = () => {};
    window.HTMLElement.prototype.scrollIntoView = () => {};
    window.matchMedia = () => ({ matches: false });
    window.CSS = { escape: value => value };
    window.fetch = async url => ({
      ok: true,
      json: async () => url === '/api/me' ? { username: 'Test' }
        : url === '/api/data' ? {}
        : { genres: [], results: [], total_pages: 1 },
    });
    run(fs.readFileSync('public/assets/ui.js', 'utf8'));
    for (const script of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
      if (script[1].trim()) run(script[1]);
    }
    await settle();
    const doc = window.document;
    assert.equal(doc.querySelectorAll('#nav button').length, 5);
    assert.equal(doc.querySelectorAll('#mobileNav button').length, 5);
    assert.equal(doc.querySelectorAll('#homeDashboard .homeDashCard').length, 4);
    assert.match(doc.querySelector('#recentWrap').textContent, /Пока нет/);
    assert.equal(doc.querySelector('#authScreen').classList.contains('hidden'), true);

    // Data changes from the legacy layer must refresh React without stale cards.
    run(`movies = [{
      id: 'fixture', name: 'Тестовый фильм', status: 'watched',
      createdAt: Date.now(), scores: { overall: 9, engage: 9, emotions: 9 }
    }]; renderHome();`);
    await settle();
    assert.match(doc.querySelector('#recentWrap').textContent, /Тестовый фильм/);
    assert.match(doc.querySelector('#recentWrap .scoreBadge').textContent, /9/);
    doc.querySelector('#recentWrap button').click();
    await settle();
    assert.equal(window.location.pathname, '/rated');
    assert.equal(doc.querySelector('#view-rated').classList.contains('hidden'), false);
    assert.equal(doc.querySelector('#nav [aria-current]').textContent, 'Оценённые');

    doc.querySelector('#brandRoot a').click();
    await settle();
    assert.equal(window.location.pathname, '/');
    doc.querySelectorAll('#mobileNav button')[1].click();
    await settle();
    assert.equal(window.location.pathname, '/search');
    assert.equal(doc.querySelector('#view-search').classList.contains('hidden'), false);
    window.history.back();
    await settle();
    assert.equal(window.location.pathname, '/');
    assert.equal(doc.querySelector('#nav [aria-current]').textContent, 'Главная');

    for (let i = 0; i < 5; i++) run('renderNav(); renderHome();');
    await settle();
    assert.equal(doc.querySelectorAll('#nav button').length, 5);
    assert.equal(doc.querySelectorAll('#recentWrap button').length, 1);
    run('movies = []; renderHome();');
    await settle();
    assert.equal(doc.querySelectorAll('#recentWrap button').length, 0);
    assert.match(doc.querySelector('#recentWrap').textContent, /Пока нет/);
    assert.deepEqual(errors, []);

    // The React home widget persists episode marks through the existing state.
    run(`nowState.imdbID = 'tt-series-test'; nowState.title = 'Тестовый сериал';
      nowState.watched = {}; omdbEpCache['tt-series-test'] = {
        totalEpisodes: 2, seasons: { '1': [
          { Episode: '1', Title: 'Первая' }, { Episode: '2', Title: 'Вторая' }
        ] }
      }; renderNowHomeWidget();`);
    await settle();
    assert.match(doc.querySelector('#nowWidgetHome').textContent, /Тестовый сериал/);
    doc.querySelector('#nowWidgetHome .primary').click();
    await settle();
    assert.equal(run("nowState.watched.S1E1"), true);
    assert.equal(JSON.parse(window.localStorage.getItem('netfly_now_v1')).watched.S1E1, true);
    assert.match(doc.querySelector('#nowWidgetHome .nowSub').textContent, /1\/2/);
    run("nowState.imdbID = null; renderNowHomeWidget();");
    await settle();
    assert.equal(doc.querySelector('#nowWidgetHome').textContent, '');

    // Card actions must remain outside summary and usable when closed.
    run(`movies = [
      { id: 'rated-test', name: 'Rated', status: 'watched', scores: {} },
      { id: 'wish-test', name: 'Wish', status: 'wish', scores: {},
        tags: ['драма'], queueOrder: 1, omdb: { type: 'movie' } },
      { id: 'wish-move', name: 'Move me', status: 'wish', scores: {},
        queueOrder: 2, omdb: { type: 'movie' } }
    ]; goTo('rated');`);
    await settle();
    const ratedCard = doc.querySelector('#items details');
    const ratedShell = ratedCard.closest('.itemShell');
    assert.equal(ratedCard.open, false);
    assert.equal(ratedShell.querySelector('.favoriteToggle').closest('details'), null);
    ratedShell.querySelector('.favoriteToggle').click();
    assert.equal(ratedCard.open, false);
    assert.equal(ratedShell.querySelector('.favoriteToggle').classList.contains('favOn'), true);
    ratedCard.querySelector('summary').click();
    await settle();
    assert.equal(ratedCard.open, true);
    run("goTo('wish');");
    await settle();
    const wishShell = doc.querySelector('#wishMoviesList .itemShell');
    const moveShell = doc.querySelector('#wishMoviesList .itemShell[data-id="wish-move"]');
    const moveButton = moveShell.querySelector('[title="Переместить в оценённые"]');
    wishShell.querySelector('.favoriteToggle').click();
    assert.equal(moveButton.textContent, '✓');
    assert.equal(doc.querySelectorAll('summary button, summary a[href], summary input, summary select, summary textarea, summary [tabindex]').length, 0);
    assert.equal(wishShell.querySelector('.tagsInline').closest('.itemBody') !== null, true);
    moveButton.click();
    await settle();
    assert.equal(doc.querySelectorAll('#items .itemShell').length, 2);
    assert.ok(doc.querySelector('#items [title="Поставить оценку"]'));
    doc.querySelector('#items [title="Поставить оценку"]').click();
    await settle();
    assert.equal(window.location.pathname, '/evaluate');
    assert.equal(doc.querySelector('#addBtn').textContent, 'Сохранить оценку');
    const editedId = run('editingMovieId');
    const nameInput = doc.getElementById('evaluate-name');
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(nameInput, 'Оценка через React');
    nameInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    const scoreInput = doc.getElementById('score-overall');
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(scoreInput, '8');
    scoreInput.dispatchEvent(new window.Event('input', { bubbles: true }));
    doc.querySelector('.evaluateReact').dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));
    await settle();
    const persistedEdit = JSON.parse(window.localStorage.getItem('netfly_movies_v6'));
    assert.equal(persistedEdit.filter(movie => movie.id === editedId).length, 1);
    assert.equal(persistedEdit.find(movie => movie.id === editedId).name, 'Оценка через React');
    assert.equal(persistedEdit.find(movie => movie.id === editedId).scores.overall, 8);
    run("goTo('wish');");
    await settle();
    run("deleteMovie('wish-test', { softEl: document.querySelector('#wishMoviesList details') });");
    await settle();
    assert.equal(doc.querySelectorAll('#wishMoviesList .itemShell').length, 0);
    assert.deepEqual(errors, []);

    const calls = [];
    let delayedMovie;
    let failMovie = false;
    const film = {
      id: 101, title: 'React фильм', release_date: '2020-01-01',
      poster_path: '/poster.jpg', vote_average: 8, overview: 'Описание фильма',
      external_ids: { imdb_id: 'tt0101' }, genres: [{ id: 18, name: 'Драма' }],
      credits: { cast: [{ id: 202, name: 'Актёр', profile_path: '/actor.jpg' }],
        crew: [{ id: 203, name: 'Режиссёр', job: 'Director' }] },
      videos: { results: [{ key: 'example', site: 'YouTube', type: 'Trailer' }] },
      similar: { results: [{ id: 102, title: 'Похожий фильм' }] },
    };
    window.fetch = async url => {
      url = String(url);
      calls.push(url);
      if(url === '/api/tmdb/movie/999') return new Promise(resolve => { delayedMovie = resolve; });
      if(url === '/api/tmdb/movie/101') return { ok: !failMovie, json: async () => failMovie ? { error: 'Тестовая ошибка' } : film };
      if(url.startsWith('/api/tmdb/person/')) return { ok: true, json: async () => ({
        id: 202, name: 'Актёр', biography: 'Биография', combined_credits: {
          cast: [{ ...film, media_type: 'movie' }], crew: [{ ...film, media_type: 'movie' }],
        },
      }) };
      if(url.startsWith('/api/tmdb/genres')) return { ok: true, json: async () => ({ genres: [{ id: 18, name: 'Драма' }] }) };
      if(url.startsWith('/api/tmdb/random')) return { ok: true, json: async () => ({ ...film, media_type: 'movie' }) };
      return { ok: true, json: async () => ({
        results: [{ id: 202, name: 'Актёр', media_type: 'person' }, { ...film, media_type: 'movie' }],
        total_pages: 2,
      }) };
    };
    const waitForSearch = () => new Promise(resolve => setTimeout(resolve, 420));
    function input(id, value) {
      const el = doc.getElementById(id);
      if(el.tagName === 'SELECT') {
        el.value = value;
        el.dispatchEvent(new window.Event('change', { bubbles: true }));
      } else {
        Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
        el.dispatchEvent(new window.Event('input', { bubbles: true }));
      }
    }
    run("goTo('search');");
    await waitForSearch();
    assert.match(doc.querySelector('#tmdbResults .catalogLink').textContent, /React фильм/);
    input('tmdbSearchInput', 'React');
    await waitForSearch();
    assert.ok(calls.some(url => url.includes('/search?query=React')));
    doc.querySelector('#tmdbPagination button:last-child').click();
    await waitForSearch();
    assert.ok(calls.some(url => url.includes('page=2')));
    const poster = doc.querySelector('#tmdbResults img');
    poster.dispatchEvent(new window.Event('error'));
    await settle();
    const retryPoster = doc.querySelector('#tmdbResults .searchPosterFallback button');
    assert.ok(retryPoster);
    retryPoster.click();
    await settle();
    assert.match(poster.src, /retry=/);
    poster.dispatchEvent(new window.Event('load'));
    await settle();
    assert.equal(doc.querySelector('#tmdbResults .searchPosterFallback button'), null);
    doc.querySelector('#tmdbResults .catalogLink').click();
    await settle(); await settle();
    assert.equal(window.location.pathname, '/movie/101');
    assert.equal(doc.querySelector('.movieHeroInfo h1').textContent, 'React фильм');
    assert.ok(doc.querySelector('.trailerFrame iframe'));
    doc.querySelector('.movieCastGrid .catalogLink').click();
    await settle(); await settle();
    assert.equal(window.location.pathname, '/person/202');
    assert.equal(doc.querySelectorAll('#personFilmography .catalogCard').length, 1);
    assert.equal(doc.querySelector('.trailerFrame iframe'), null);
    doc.querySelector('#personFilmography .catalogLink').click();
    await settle(); await settle();
    doc.getElementById('rateMovieBtn').click();
    await settle();
    assert.equal(window.location.pathname, '/evaluate');
    assert.equal(doc.getElementById('movieName').value, 'React фильм');
    assert.equal(doc.getElementById('director').value, 'Режиссёр');
    run("goTo('movie', { tmdbId: 101, type: 'movie' });");
    await settle(); await settle();
    doc.getElementById('movieAddWishBtn').click();
    await settle();
    assert.equal(window.location.pathname, '/wish');
    assert.equal(run("movies.filter(m => m.omdb?.tmdbId === 101 && m.status === 'wish').length"), 1);
    run("goTo('search');");
    await waitForSearch();
    assert.equal(doc.getElementById('tmdbSearchInput').value, 'React');
    input('tmdbYearFilter', '2020');
    input('tmdbDirectorFilter', 'Нолан');
    await settle();
    doc.getElementById('tmdbRandomBtn').click();
    await settle(); await settle();
    const randomUrl = new URL(calls.findLast(url => url.startsWith('/api/tmdb/random')), 'http://localhost');
    assert.equal(randomUrl.searchParams.get('year'), '2020');
    assert.equal(randomUrl.searchParams.get('director'), 'Нолан');
    assert.equal(doc.getElementById('movieAddWishBtn'), null);
    run("goTo('movie', { tmdbId: 999, type: 'movie' });");
    await settle();
    run("goTo('person', { personId: 202 });");
    await settle(); await settle();
    delayedMovie({ ok: true, json: async () => ({ ...film, title: 'Устаревший результат' }) });
    await settle();
    assert.equal(doc.querySelector('.personBio h1').textContent, 'Актёр');
    assert.equal(doc.querySelector('.movieHero'), null);
    failMovie = true;
    run("goTo('movie', { tmdbId: 101, type: 'movie' });");
    await settle(); await settle();
    assert.match(doc.querySelector('#moviePageContent [role=alert]').textContent, /Тестовая ошибка/);
    failMovie = false;
    doc.querySelector('#moviePageContent [role=alert] button').click();
    await settle(); await settle();
    assert.equal(doc.querySelector('.movieHeroInfo h1').textContent, 'React фильм');
    assert.deepEqual(errors, []);
    const previousFetch = window.fetch;
    let resolveOldSearch;
    window.fetch = async url => {
      if (String(url).includes('query=old-query')) {
        return new Promise(resolve => { resolveOldSearch = resolve; });
      }
      return previousFetch(url);
    };
    run("goTo('search');");
    await settle();
    input('tmdbSearchInput', 'old-query');
    await waitForSearch();
    input('tmdbSearchInput', 'new-query');
    await waitForSearch();
    resolveOldSearch({ ok: true, json: async () => ({ results: [{ id: 888, title: 'Старый ответ' }] }) });
    await settle();
    assert.match(doc.querySelector('#tmdbResults').textContent, /React фильм/);
    assert.doesNotMatch(doc.querySelector('#tmdbResults').textContent, /Старый ответ/);
    window.fetch = async url => String(url) === '/api/tmdb/tv/303'
      ? { ok: true, json: async () => ({ ...film, id: 303, title: undefined, name: 'React сериал', external_ids: {}, first_air_date: '2021-01-01' }) }
      : previousFetch(url);
    run("goTo('movie', { tmdbId: 303, type: 'tv' });");
    await settle(); await settle();
    assert.equal(doc.querySelector('.movieHeroInfo h1').textContent, 'React сериал');
    doc.getElementById('movieAddWishBtn').click();
    await settle();
    assert.equal(run("movies.find(m => m.omdb?.tmdbId === 303).omdb.type"), 'series');
    assert.equal(run("movies.find(m => m.omdb?.tmdbId === 303).omdb.imdbID"), 'tmdb-tv-303');
    assert.deepEqual(errors, []);
  } finally {
    window.close();
  }
}
test().then(() => console.log('Integration passed: navigation/history, card accessibility, live search, pagination, poster retry, movie/person routes, rating form, queue, random filters, stale requests and API retry.'))
  .catch(error => { console.error(error); process.exitCode = 1; });
