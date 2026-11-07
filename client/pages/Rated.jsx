import React, { useEffect, useMemo, useRef, useState } from 'react';

const CRITERIA = [
  ['overall', 'Общее впечатление'],
  ['engage', 'Вовлечённость'],
  ['emotions', 'Эмоции после просмотра'],
];

function score(movie) {
  const values = CRITERIA.map(([key]) => Math.max(0, Math.min(10, Number(movie?.scores?.[key] ?? 0))));
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function finalScore(value) {
  return Number.isFinite(value) && value > 0 ? Math.min(value, 10).toFixed(1) : '—';
}

function statusLabel(status) {
  return ({ watched: 'Оценено', rewatch: 'Пересматриваю', dropped: 'Бросил' }[status] || 'Оценено');
}

function Highlight({ children, query }) {
  const text = String(children ?? '');
  const index = query ? text.toLocaleLowerCase().indexOf(query.toLocaleLowerCase()) : -1;
  if (index < 0) return text;
  return <>{text.slice(0, index)}<mark>{text.slice(index, index + query.length)}</mark>{text.slice(index + query.length)}</>;
}

function Poster({ src, title, large = false }) {
  const [failed, setFailed] = useState(!src);
  const [attempt, setAttempt] = useState(0);
  const className = large ? 'posterBigImg' : 'thumb';
  return <div className={className}>
    {src && !failed && <img src={src + (attempt ? `?retry=${attempt}` : '')} alt={title} loading="lazy" onError={() => setFailed(true)} />}
    {failed && <><span>{large ? 'Нет постера' : 'Нет\nпостера'}</span>{src && <button type="button" className="posterRetry" onClick={() => { setFailed(false); setAttempt(Date.now()); }}>↻</button>}</>}
  </div>;
}

function InfoGrid({ children }) { return <div className="infoGrid">{children}</div>; }
function Info({ label, children }) { return <div className="kv"><span>{label}</span><b>{children || '—'}</b></div>; }

function RatedCard({ movie, query, open, grid, onToggle, onToggleFavorite, onDelete, onRate, onTagFilter, onOpenPerson, setRef }) {
  const tags = Array.isArray(movie.tags) ? movie.tags : [];
  const actors = Array.isArray(movie.omdb?.actors) ? movie.omdb.actors.slice(0, 3) : [];
  const poster = movie.omdb?.posterUrl || null;
  const favorite = !!movie.favorite;
  const currentScore = score(movie);
  const date = new Date(movie.createdAt || Date.now()).toLocaleString('ru-RU', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  });
  const ref = useRef(null);
  useEffect(() => { setRef(movie.id, ref.current); return () => setRef(movie.id, null); }, [movie.id, setRef]);

  return <div className={'itemShell' + (grid && open ? ' gridOpen' : '')} data-id={movie.id} ref={ref}>
    <details className="item" open={open} onToggle={event => {
      // Ignore the native toggle emitted when React applies the controlled
      // `open` prop after a move from the queue.
      if (event.currentTarget.open !== open) onToggle();
    }}>
      <summary>
        <div className="sumLeft">
          <Poster src={poster} title={movie.name} />
          <div className="sumText">
            <div className="titleLine">
              <p className="title"><Highlight query={query}>{movie.name}</Highlight></p>
              {movie.year && <span className="tagPill">{movie.year}</span>}
              {Number(movie?.scores?.emotions ?? 0) >= Number(movie?.scores?.overall ?? 0) + 2 && <span className="tagPill" title="Эмоции заметно выше общего впечатления">🔥</span>}
              <span className="tagPill">{statusLabel(movie.status)}</span>
              {favorite && <span className="tagPill">⭐</span>}
            </div>
            <div className="metaLine">
              <span className="badgeRed">{finalScore(currentScore)}</span>
              {movie.omdb?.genre && <span className="chip">{movie.omdb.genre}</span>}
              {!!tags.length && <span className="chip">Теги: <b><Highlight query={query}>{tags.join(', ')}</Highlight></b></span>}
            </div>
          </div>
        </div>
      </summary>
      <div className="itemBody">
        <div className="posterBig">
          <Poster src={poster} title={movie.name} large />
          <div className="posterMeta">
            <InfoGrid>
              <Info label="Жанры">{movie.omdb?.genre}</Info>
              <Info label="Длительность">{movie.omdb?.runtime}</Info>
              <Info label="IMDb рейтинг">{movie.omdb?.imdbRating}</Info>
              <Info label="Тип">{movie.omdb?.type === 'series' ? 'Сериал' : movie.omdb?.type === 'movie' ? 'Фильм' : movie.omdb?.type}</Info>
              <Info label="IMDb">{movie.omdb?.imdbID ? <a className="imdbLink" href={`https://www.imdb.com/title/${encodeURIComponent(movie.omdb.imdbID)}/`} target="_blank" rel="noopener noreferrer">Открыть ↗</a> : null}</Info>
            </InfoGrid>
          </div>
        </div>
        <InfoGrid>
          <Info label="Режиссёр(ы)">{movie.director}</Info>
          <Info label="Год">{movie.year}</Info>
          <Info label="Статус">{statusLabel(movie.status)}</Info>
          <Info label="Добавлено">{date}</Info>
        </InfoGrid>
        <div className="textBlock"><div className="k">Актёры</div><div className="v">
          {actors.length ? <div className="actorChips">{actors.map(actor => <button key={actor} type="button" className="tagChip actorChip" onClick={() => onOpenPerson(actor)}>{actor}</button>)}</div> : '—'}
        </div></div>
        <InfoGrid>{CRITERIA.map(([key, label]) => <Info key={key} label={label}>{movie.scores?.[key]}</Info>)}</InfoGrid>
        <div className="textBlock"><div className="k">Теги</div><div className="v">
          {tags.length ? <div className="tagLinks">{tags.map(tag => <button key={tag} type="button" className="tagLink" onClick={() => onTagFilter(tag)}>{tag}</button>)}</div> : '—'}
        </div></div>
        <div className="textBlock"><div className="k">Заметки</div><div className="v notesText">{movie.notes?.trim() || '—'}</div></div>
        <div className="actionsRow"><button className="danger" type="button" onClick={() => onDelete(movie.id, ref.current)}>Удалить</button></div>
      </div>
    </details>
    <div className="sumRight">
      <div className="quickActions">
        {currentScore <= 0 && <button type="button" className="iconBtn rateMini" title="Поставить оценку" onClick={() => onRate?.(movie)}>＋</button>}
        <button type="button" className={'iconBtn favoriteToggle' + (favorite ? ' favOn' : '')} title={favorite ? 'Убрать из избранного' : 'В избранное'} onClick={() => onToggleFavorite(movie.id)}>{favorite ? '⭐' : '☆'}</button>
        <button type="button" className="iconBtn dangerMini" title="Удалить" onClick={() => onDelete(movie.id, ref.current)}>🗑</button>
      </div>
    </div>
  </div>;
}

export function Rated({ list = [], total = 0, page = 1, pageSize = 20, viewMode = 'list', query = '', onToggleFavorite, onDelete, onRate, onTagFilter, onOpenPerson, openId }) {
  const [openCard, setOpenCard] = useState(null);
  const [favoriteRevision, setFavoriteRevision] = useState(0);
  const refs = useRef(new Map());
  const openedIdRef = useRef(null);
  const shown = useMemo(() => list.slice((page - 1) * pageSize, page * pageSize), [list, page, pageSize]);
  void favoriteRevision;

  useEffect(() => {
    if (!openId) {
      openedIdRef.current = null;
      return;
    }
    if (openedIdRef.current === openId) return;
    openedIdRef.current = openId;
    setOpenCard(openId);
    requestAnimationFrame(() => refs.current.get(openId)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  }, [openId, shown]);

  const setRef = (id, element) => { if (element) refs.current.set(id, element); else refs.current.delete(id); };
  return <>
    {shown.length ? shown.map(movie => <RatedCard key={movie.id} movie={movie} query={query} grid={viewMode === 'grid'} open={openCard === movie.id}
      onToggle={() => setOpenCard(current => current === movie.id ? null : movie.id)}
      onToggleFavorite={id => { onToggleFavorite(id); setFavoriteRevision(value => value + 1); }}
      onDelete={onDelete} onRate={onRate} onTagFilter={onTagFilter} onOpenPerson={onOpenPerson} setRef={setRef} />)
      : <div className="empty">{total ? <>Ничего не найдено.<br /><span style={{ opacity: .8 }}>Попробуй изменить фильтры.</span></> : 'Пока пусто. Перейди в “Оценить” и добавь первый фильм 🙂'}</div>}
  </>;
}

function normalize(value) { return String(value ?? '').trim().toLocaleLowerCase(); }

function matchesMovie(movie, query) {
  if (!query) return true;
  const actors = Array.isArray(movie?.omdb?.actors) ? movie.omdb.actors.join(' ') : '';
  return normalize([
    movie?.name, movie?.director, actors, movie?.tags?.join(' '), movie?.omdb?.genre,
    movie?.omdb?.writer, movie?.omdb?.plot,
  ].join(' ')).includes(query);
}

function filteredMovies(movies, filters) {
  let result = movies.filter(movie => (movie.status || 'watched') !== 'wish');
  const query = normalize(filters.query);
  const tag = normalize(filters.tag);
  const genre = normalize(filters.genre);
  const director = normalize(filters.director);
  const actor = normalize(filters.actor);

  if (query) result = result.filter(movie => matchesMovie(movie, query));
  if (Number(filters.minAvg) > 0) result = result.filter(movie => score(movie) >= Number(filters.minAvg));
  if (tag) result = result.filter(movie => (movie.tags || []).some(value => normalize(value) === tag));
  if (filters.onlyFav) result = result.filter(movie => !!movie.favorite);
  if (String(filters.year || '').trim()) result = result.filter(movie => String(movie.year || '') === String(filters.year).trim());
  if (genre) result = result.filter(movie => normalize(movie.omdb?.genre).includes(genre));
  if (director) result = result.filter(movie => normalize(movie.director || movie.omdb?.director).includes(director));
  if (actor) result = result.filter(movie => (movie.omdb?.actors || []).some(value => normalize(value).includes(actor)));
  if (filters.status) result = result.filter(movie => (movie.status || 'watched') === filters.status);

  const sort = filters.sort;
  result.sort((a, b) => {
    if (sort === 'best') return score(b) - score(a) || (b.createdAt || 0) - (a.createdAt || 0);
    if (sort === 'emotions') return Number(b.scores?.emotions || 0) - Number(a.scores?.emotions || 0) || (b.createdAt || 0) - (a.createdAt || 0);
    if (sort === 'engage') return Number(b.scores?.engage || 0) - Number(a.scores?.engage || 0) || (b.createdAt || 0) - (a.createdAt || 0);
    if (sort === 'name') return normalize(a.name).localeCompare(normalize(b.name), 'ru');
    if (sort === 'year_desc') return Number(b.year || -1) - Number(a.year || -1);
    return (b.createdAt || 0) - (a.createdAt || 0);
  });
  return result;
}

const defaultFilters = {
  query: '', sort: 'new', minAvg: '0', tag: '', year: '', genre: '', director: '', actor: '', status: '', onlyFav: false,
};

export function RatedPage({ movies = [], pageSize = 20, filters: initialFilters, page: initialPage = 1, viewMode: initialViewMode = 'list', onStateChange, onToggleFavorite, onDelete, onRate, onOpenPerson, onClearAll, openId }) {
  const [state, setState] = useState({
    filters: { ...defaultFilters, ...(initialFilters || {}) },
    page: initialPage,
    viewMode: initialViewMode === 'grid' ? 'grid' : 'list',
    filtersOpen: false,
  });
  const [favoriteRevision, setFavoriteRevision] = useState(0);
  const list = useMemo(() => filteredMovies(movies, state.filters), [movies, state.filters, favoriteRevision]);
  const total = movies.filter(movie => (movie.status || 'watched') !== 'wish').length;
  const totalPages = Math.max(1, Math.ceil(list.length / pageSize));
  const page = Math.max(1, Math.min(state.page, totalPages));
  const query = normalize(state.filters.query);
  const average = total ? movies.filter(movie => (movie.status || 'watched') !== 'wish').reduce((sum, movie) => sum + score(movie), 0) / total : null;
  const best = movies.filter(movie => (movie.status || 'watched') !== 'wish').reduce((winner, movie) => !winner || score(movie) > score(winner) ? movie : winner, null);

  function commit(next) {
    setState(current => {
      const value = typeof next === 'function' ? next(current) : next;
      onStateChange?.(value);
      return value;
    });
  }

  function changeFilter(key, value) {
    commit(current => ({ ...current, filters: { ...current.filters, [key]: value }, page: 1 }));
  }

  function changeView(viewMode) {
    const mode = viewMode === 'grid' ? 'grid' : 'list';
    localStorage.setItem('netfly_list_view_v1_rated', mode);
    commit(current => ({ ...current, viewMode: mode }));
  }

  function clearFilters() { commit(current => ({ ...current, filters: { ...defaultFilters }, page: 1 })); }

  const field = (key, label, options) => <div className="filterRow"><label htmlFor={`rated-${key}`}>{label}</label><select id={`rated-${key}`} value={state.filters[key]} onChange={event => changeFilter(key, event.target.value)}>{options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}</select></div>;
  return <section className="card ratedReactPage">
    <div className="listHeader">
      <div className="listTop">
        <h2>Оценённые</h2>
        <div className="viewToggle" aria-label="Вид списка">
          <button type="button" className={state.viewMode === 'grid' ? 'active' : ''} onClick={() => changeView('grid')}>▦ Сетка</button>
          <button type="button" className={state.viewMode === 'list' ? 'active' : ''} onClick={() => changeView('list')}>☷ Список</button>
        </div>
        <button className="danger" type="button" onClick={onClearAll}>Очистить оценённые</button>
      </div>
      <div className="controls">
        <div><label htmlFor="rated-query">Поиск по названию</label><input id="rated-query" type="search" value={state.filters.query} placeholder="Начни вводить..." onChange={event => changeFilter('query', event.target.value)} /></div>
        {field('sort', 'Сортировка', [['new', 'Сначала новые'], ['best', 'По лучшей оценке'], ['emotions', 'По эмоциям'], ['engage', 'По вовлечённости'], ['name', 'По названию (А→Я)'], ['year_desc', 'По году (новые→старые)']])}
      </div>
      <button type="button" className="filtersToggle" aria-expanded={state.filtersOpen} onClick={() => commit(current => ({ ...current, filtersOpen: !current.filtersOpen }))}>{state.filtersOpen ? '− Скрыть фильтры' : '＋ Фильтры'}</button>
      <div className={'filters ratedReactFilters ' + (state.filtersOpen ? 'isOpen' : 'isClosed')}>
        {field('minAvg', 'Минимальная оценка', [['0', 'Любая'], ['6', '≥ 6.0'], ['7', '≥ 7.0'], ['8', '≥ 8.0'], ['9', '≥ 9.0']])}
        <div className="filterRow"><label htmlFor="rated-tag">Фильтр по тегу</label><input id="rated-tag" type="text" value={state.filters.tag} placeholder="например: драма" onChange={event => changeFilter('tag', event.target.value)} /><div className="inline"><input id="rated-fav" type="checkbox" checked={state.filters.onlyFav} onChange={event => changeFilter('onlyFav', event.target.checked)} /><label htmlFor="rated-fav">Только избранное</label></div></div>
        <div className="filterRow"><label htmlFor="rated-year">Год</label><input id="rated-year" type="number" value={state.filters.year} placeholder="например: 2008" onChange={event => changeFilter('year', event.target.value)} /></div>
        <div className="filterRow"><label htmlFor="rated-genre">Жанр</label><input id="rated-genre" type="text" value={state.filters.genre} placeholder="например: драма" onChange={event => changeFilter('genre', event.target.value)} /></div>
        <div className="filterRow"><label htmlFor="rated-director">Режиссёр</label><input id="rated-director" type="text" value={state.filters.director} placeholder="например: Нолан" onChange={event => changeFilter('director', event.target.value)} /></div>
        <div className="filterRow"><label htmlFor="rated-actor">Актёр</label><input id="rated-actor" type="text" value={state.filters.actor} placeholder="например: Бэйл" onChange={event => changeFilter('actor', event.target.value)} /></div>
        {field('status', 'Статус', [['', 'Все статусы'], ['watched', 'Оценено'], ['rewatch', 'Пересматриваю'], ['dropped', 'Бросил']])}
        <button type="button" onClick={clearFilters}>Сбросить фильтры</button>
      </div>
      <div className="small">Оценённых: {total}{list.length !== total ? ` • Показано: ${list.length}` : ''} • Средняя оценка: {average === null ? '—' : finalScore(average)}{best ? ` • Лучший: ${best.name} (${finalScore(score(best))})` : ''}</div>
    </div>
    <div id="items" className={'items ratedReactHost' + (state.viewMode === 'grid' ? ' posterGrid' : '')}>
      <Rated list={list} total={total} page={page} pageSize={pageSize} viewMode={state.viewMode} query={query} onToggleFavorite={id => { onToggleFavorite(id); setFavoriteRevision(value => value + 1); }} onDelete={onDelete} onRate={onRate} onTagFilter={tag => changeFilter('tag', tag)} onOpenPerson={onOpenPerson} openId={openId} />
    </div>
    <div className="summary" style={{ marginTop: 12 }}><div className="small">Страница {page} из {totalPages}</div><div className="btns"><button type="button" disabled={page <= 1} onClick={() => commit(current => ({ ...current, page: current.page - 1 }))}>←</button><button type="button" disabled={page >= totalPages} onClick={() => commit(current => ({ ...current, page: current.page + 1 }))}>→</button></div></div>
  </section>;
}
