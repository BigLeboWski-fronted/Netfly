import React, { useEffect, useMemo, useRef, useState } from 'react';

function normalize(value) { return String(value ?? '').trim().toLocaleLowerCase(); }
function kindOf(movie) { return ['series', 'tv-series'].includes(String(movie?.omdb?.type || '').toLowerCase()) ? 'series' : 'movie'; }
function score(movie) {
  const values = ['overall', 'engage', 'emotions'].map(key => Math.max(0, Math.min(10, Number(movie?.scores?.[key] ?? 0))));
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}
function formatScore(value) { return Number.isFinite(value) && value > 0 ? value.toFixed(1) : ''; }
function formatAge(createdAt) {
  const days = Math.max(0, Math.floor((Date.now() - Number(createdAt || Date.now())) / 86400000));
  if (!days) return 'В очереди: сегодня';
  if (days === 1) return 'В очереди: 1 день';
  if (days < 30) return `В очереди: ${days} дн.`;
  const months = Math.floor(days / 30);
  return `В очереди: ${months} ${months === 1 ? 'месяц' : 'мес.'}`;
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

function Info({ label, value }) { return <div className="kv"><span>{label}</span><b>{value || '—'}</b></div>; }

function WishCard({ movie, index, query, open, grid, dragging, onToggle, onToggleFavorite, onMove, onDelete, onOpenPerson, onReason, onDragStart, onDragEnd, onDrop, onTagFilter, setRef }) {
  const [reason, setReason] = useState(movie.wishReason || '');
  const ref = useRef(null);
  const tags = Array.isArray(movie.tags) ? movie.tags : [];
  const actors = Array.isArray(movie.omdb?.actors) ? movie.omdb.actors.slice(0, 3) : [];
  const poster = movie.omdb?.posterUrl || null;
  const favorite = !!movie.favorite;
  const kind = kindOf(movie) === 'series' ? 'Сериал' : 'Фильм';
  const imdb = movie.omdb?.imdbID ? `https://www.imdb.com/title/${encodeURIComponent(movie.omdb.imdbID)}/` : null;
  const kinoUrl = `https://kino.pub/item/search?type=${kind === 'Сериал' ? 'serial' : 'movie'}&mode=&query=${encodeURIComponent(movie.name || '')}`;
  useEffect(() => { setRef(movie.id, ref.current); return () => setRef(movie.id, null); }, [movie.id, setRef]);

  return <div className={'itemShell' + (grid && open ? ' gridOpen' : '') + (dragging ? ' dragging' : '')} data-id={movie.id} ref={ref} onDragOver={event => { event.preventDefault(); if (!dragging) event.currentTarget.classList.add('dropTarget'); }} onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget)) event.currentTarget.classList.remove('dropTarget'); }} onDrop={event => { event.preventDefault(); event.currentTarget.classList.remove('dropTarget'); onDrop(movie.id); }}>
    <details className="item" open={open} onToggle={event => {
      // React controls the open state. Ignore the browser's toggle event when
      // it was caused by React applying `open`, otherwise random/openId can
      // immediately flip the card closed again.
      if (event.currentTarget.open !== open) onToggle();
    }}>
      <summary>
        <div className="sumLeft">
          <Poster src={poster} title={movie.name} />
          <div className="sumText">
            <div className="titleLine">
              <p className="title">{movie.name}</p>
              <span className="tagPill">{kind}</span>
              {movie.year && <span className="tagPill">{movie.year}</span>}
              <span className="chip orderPill">№{index + 1}</span>
              {favorite && <span className="tagPill">⭐</span>}
            </div>
            <div className="metaLine">
              {formatScore(score(movie)) && <span className="badgeRed">Оценка: {formatScore(score(movie))}</span>}
              {movie.omdb?.genre && <span className="chip">{movie.omdb.genre}</span>}
              <span className="chip">{formatAge(movie.createdAt)}</span>
              {movie.wishReason?.trim() && <span className="chip reasonChip">Почему: {movie.wishReason.trim()}</span>}
            </div>
          </div>
        </div>
      </summary>
      <div className="itemBody">
        <div className="posterBig">
          <Poster src={poster} title={movie.name} large />
          <div className="posterMeta"><div className="infoGrid">
            <Info label="Жанры" value={movie.omdb?.genre} />
            <Info label="Длительность" value={movie.omdb?.runtime} />
            <Info label="IMDb рейтинг" value={movie.omdb?.imdbRating} />
            <Info label="Тип" value={kind} />
            <Info label="IMDb" value={imdb ? <a className="imdbLink" href={imdb} target="_blank" rel="noopener noreferrer">Открыть ↗</a> : null} />
          </div></div>
        </div>
        <div className="infoGrid">
          <Info label="Режиссёр(ы)" value={movie.director} />
          <Info label="Год" value={movie.year} />
          <Info label="Очередь" value={`№${index + 1}`} />
          <Info label="Добавлено" value={new Date(movie.createdAt || Date.now()).toLocaleString('ru-RU')} />
        </div>
        <div className="textBlock"><div className="k">Актёры</div><div className="v">{actors.length ? <div className="actorChips">{actors.map(actor => <button key={actor} type="button" className="tagChip actorChip" onClick={() => onOpenPerson(actor)}>{actor}</button>)}</div> : '—'}</div></div>
        <div className="textBlock"><div className="k">Теги</div><div className="v">{tags.length ? <div className="tagLinks tagsInline">{tags.map(tag => <button key={tag} type="button" className="tagLink" onClick={() => onTagFilter(tag)}>{tag}</button>)}</div> : '—'}</div></div>
        <div className="textBlock"><div className="k">Заметки</div><div className="v notesText">{movie.notes?.trim() || '—'}</div></div>
        <div className="textBlock"><div className="k">Почему хочу посмотреть</div><div className="v"><input className="reasonInput" type="text" value={reason} placeholder="Например: советовали / люблю такие сюжеты" onChange={event => { setReason(event.target.value); onReason(movie.id, event.target.value); }} /></div></div>
        <div className="actionsRow"><button className="danger" type="button" onClick={() => onDelete(movie.id, ref.current)}>Удалить</button></div>
      </div>
    </details>
    <div className="sumRight"><div className="quickActions">
      <button type="button" className={'iconBtn favoriteToggle' + (favorite ? ' favOn' : '')} title={favorite ? 'Убрать из избранного' : 'В избранное'} onClick={() => onToggleFavorite(movie.id)}>{favorite ? '⭐' : '☆'}</button>
      <button type="button" className="iconBtn" title="Переместить в оценённые" onClick={() => onMove(movie.id)}>✓</button>
      <button type="button" className="iconBtn kinoBtn" title="Искать на kino.pub" onClick={() => window.open(kinoUrl, '_blank', 'noopener,noreferrer')}>KP</button>
      <button type="button" className="iconBtn dangerMini" title="Удалить" onClick={() => onDelete(movie.id, ref.current)}>🗑</button>
      <button type="button" className="dragHandle" draggable="true" title="Перетащить" onDragStart={event => {
        event.stopPropagation();
        if (ref.current) {
          const bounds = ref.current.getBoundingClientRect();
          event.dataTransfer.setDragImage(ref.current, event.clientX - bounds.left, event.clientY - bounds.top);
        }
        event.dataTransfer.setData('text/plain', movie.id);
        event.dataTransfer.effectAllowed = 'move';
        onDragStart(event, movie.id);
      }} onDragEnd={onDragEnd}>≡</button>
    </div></div>
  </div>;
}

export function WishPage({ movies = [], initialKind = 'movie', initialViewMode = 'list', initialQuery = '', onStateChange, onToggleFavorite, onMove, onDelete, onOpenPerson, onReason, onReorder, onClear, onRandom, openId }) {
  const [state, setState] = useState({ kind: initialKind === 'series' ? 'series' : 'movie', viewMode: 'list', query: initialQuery || '' });
  const [openCard, setOpenCard] = useState(null);
  const [dragId, setDragId] = useState(null);
  const [favoriteRevision, setFavoriteRevision] = useState(0);
  const refs = useRef(new Map());
  const openedIdRef = useRef(null);
  const list = useMemo(() => movies.filter(movie => (movie.status || 'watched') === 'wish' && kindOf(movie) === state.kind && !movie.isNow && normalize([movie.name, movie.director, movie.tags?.join(' '), movie.omdb?.genre, movie.wishReason].join(' ')).includes(normalize(state.query))).sort((a, b) => Number(a.queueOrder || 0) - Number(b.queueOrder || 0)), [movies, state.kind, state.query, favoriteRevision]);

  useEffect(() => {
    if (!openId) {
      openedIdRef.current = null;
      return;
    }
    if (openedIdRef.current === openId) return;
    openedIdRef.current = openId;
    setOpenCard(openId);
    requestAnimationFrame(() => refs.current.get(openId)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  }, [openId, list]);
  function commit(next) { setState(current => { const value = typeof next === 'function' ? next(current) : next; onStateChange?.(value); return value; }); }
  function setRef(id, element) { if (element) refs.current.set(id, element); else refs.current.delete(id); }
  function reorder(targetId) {
    if (!dragId || dragId === targetId) return;
    const ids = list.map(movie => movie.id).filter(id => id !== dragId);
    const targetIndex = ids.indexOf(targetId);
    ids.splice(targetIndex < 0 ? ids.length : targetIndex, 0, dragId);
    onReorder?.(state.kind, ids);
    const moved = refs.current.get(dragId);
    moved?.classList.add('justMoved');
    setTimeout(() => moved?.classList.remove('justMoved'), 850);
    setDragId(null);
  }
  return <section className="card wishReactPage">
    <div className="listHeader"><div className="listTop">
      <h2>Буду смотреть</h2>
      <div className="segmented wishSegment"><button type="button" className={'segBtn ' + (state.kind === 'movie' ? 'active' : '')} onClick={() => commit(current => ({ ...current, kind: 'movie' }))}>Фильмы</button><button type="button" className={'segBtn ' + (state.kind === 'series' ? 'active' : '')} onClick={() => commit(current => ({ ...current, kind: 'series' }))}>Сериалы</button></div>
      <button type="button" onClick={() => onRandom(state.kind, list)}>🎲 Случайный {state.kind === 'series' ? 'сериал' : 'фильм'}</button><button className="danger" type="button" onClick={() => onClear(state.kind)}>Очистить очередь</button>
    </div><div className="controls"><div><label htmlFor="wish-react-search">Поиск</label><input id="wish-react-search" type="search" value={state.query} placeholder="Начни вводить..." onChange={event => commit(current => ({ ...current, query: event.target.value }))} /></div></div><div className="small">В очереди: {list.length}</div></div>
    <div id={state.kind === 'series' ? 'wishSeriesList' : 'wishMoviesList'} className={'items wishReactHost' + (state.viewMode === 'grid' ? ' posterGrid' : '')}>{list.length ? list.map((movie, index) => <WishCard key={movie.id} movie={movie} index={index} query={state.query} grid={state.viewMode === 'grid'} dragging={dragId === movie.id} open={openCard === movie.id} onToggle={() => setOpenCard(current => current === movie.id ? null : movie.id)} onToggleFavorite={id => { onToggleFavorite(id); setFavoriteRevision(value => value + 1); }} onMove={onMove} onDelete={onDelete} onOpenPerson={onOpenPerson} onReason={onReason} onTagFilter={tag => commit(current => ({ ...current, query: tag }))} onDragStart={(event, id) => { setDragId(id); }} onDragEnd={() => setDragId(null)} onDrop={reorder} setRef={setRef} />) : <div className="empty">Очередь пуста. Добавь что-нибудь из «Оценить».</div>}</div>
  </section>;
}
