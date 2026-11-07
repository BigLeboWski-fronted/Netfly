import React, { useEffect, useRef, useState } from 'react';
import { request, itemRoute } from '../api/tmdb.js';
import { useResource } from '../hooks/useResource.js';
import { CatalogCard, ResourceStatus } from '../components/Catalog.jsx';

export function Search({ active, onNavigate }) {
  const [filters, setFilters] = useState({ query: '', type: '', genre: '', year: '', sort: 'popularity.desc', director: '', actor: '' });
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [randomState, setRandomState] = useState({});
  const randomRequest = useRef(null);
  useEffect(() => () => randomRequest.current?.abort(), []);
  useEffect(() => { if (!active) { randomRequest.current?.abort(); setRandomState({}); } }, [active]);
  const genres = useResource(active ? '/api/tmdb/genres?type=' + (filters.type || 'movie') : null);
  const params = filters.query.trim()
    ? new URLSearchParams({ query: filters.query.trim(), page })
    : new URLSearchParams({ type: filters.type || 'movie', genre: filters.genre, year: filters.year, sort: filters.sort, page });
  const url = '/api/tmdb/' + (filters.query.trim() ? 'search?' : 'discover?') + params;
  const resource = useResource(active ? url : null, 300, revision);
  const items = [...(resource.data?.results || [])].sort((a, b) => Number(a.media_type === 'person') - Number(b.media_type === 'person'));
  const pages = Math.max(1, Math.min(500, resource.data?.total_pages || 1));
  function change(key, value) {
    randomRequest.current?.abort();
    setRandomState({});
    setFilters(old => ({ ...old, [key]: value, ...(key === 'type' ? { genre: '' } : {}) }));
    setPage(1);
  }
  async function random() {
    randomRequest.current?.abort();
    const controller = new AbortController();
    randomRequest.current = controller;
    setRandomState({ loading: true });
    try {
      const { query, ...options } = filters;
      const item = await request('/api/tmdb/random?' + new URLSearchParams({ ...options, type: filters.type || 'movie' }), { signal: controller.signal });
      if (controller.signal.aborted) return;
      const route = itemRoute(item);
      setRandomState({});
      onNavigate(route.view, route.opts);
    } catch (error) {
      if (!controller.signal.aborted) setRandomState({ error: error.message });
    }
  }
  const field = (key, id, label, options) => <select id={id} aria-label={label} value={filters[key]} onChange={e => change(key, e.target.value)}>
    {options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
  </select>;
  return <section className="card">
    <h2>🔍 Поиск фильмов и сериалов</h2>
    <form onSubmit={event => { event.preventDefault(); setPage(1); setRevision(n => n + 1); }}>
      <input id="tmdbSearchInput" type="search" aria-label="Название или имя" placeholder="Введите название или имя…" value={filters.query} onChange={e => change('query', e.target.value)} />
      <div className="catalogFilters">
        {field('type', 'tmdbTypeFilter', 'Тип', [['', 'Все типы'], ['movie', 'Фильмы'], ['tv', 'Сериалы']])}
        {field('genre', 'tmdbGenreFilter', 'Жанр', [['', 'Все жанры'], ...(genres.data?.genres || []).map(g => [g.id, g.name])])}
        {field('year', 'tmdbYearFilter', 'Год', [['', 'Все годы'], ...Array.from({ length: new Date().getFullYear() - 1949 }, (_, i) => { const year = new Date().getFullYear() - i; return [year, year]; })])}
        <input id="tmdbDirectorFilter" className="tmdbPeopleFilter" aria-label="Режиссёр для случайного фильма" placeholder="Режиссёр" value={filters.director} onChange={e => change('director', e.target.value)} />
        <input id="tmdbActorFilter" className="tmdbPeopleFilter" aria-label="Актёр для случайного фильма" placeholder="Актёр" value={filters.actor} onChange={e => change('actor', e.target.value)} />
        {field('sort', 'tmdbSortFilter', 'Сортировка', [['popularity.desc', 'Популярные'], ['vote_average.desc', 'Высокий рейтинг'], ['release_date.desc', 'Новые']])}
      </div>
      <p className="small">Режиссёр и актёр учитываются при случайном выборе. Поиск по названию и имени выполняется отдельно от фильтров каталога.</p>
      {genres.error && <div role="alert" className="small">Не удалось загрузить жанры. <button type="button" onClick={genres.retry}>Повторить</button></div>}
      <div className="catalogActions"><button id="tmdbSearchBtn" type="submit" className="primary">Искать</button><button id="tmdbRandomBtn" type="button" disabled={randomState.loading} onClick={random}>{randomState.loading ? 'Ищу…' : '🎲 Случайный фильм'}</button></div>
    </form>
    {randomState.error && <p role="alert">{randomState.error}</p>}
    {resource.loading || resource.error ? <ResourceStatus resource={resource} /> : <>
      {!items.length && <p role="status">Ничего не найдено</p>}
      <div id="tmdbResults" className="catalogGrid">{items.map(item => <CatalogCard key={(item.media_type || filters.type) + ':' + item.id} item={item} onNavigate={onNavigate} />)}</div>
      {pages > 1 && <div id="tmdbPagination" className="catalogActions">
        <button type="button" disabled={page <= 1} onClick={() => setPage(n => n - 1)}>← Назад</button>
        <span>Страница {page} из {pages}</span>
        <button type="button" disabled={page >= pages} onClick={() => setPage(n => n + 1)}>Вперёд →</button>
      </div>}
    </>}
  </section>;
}
