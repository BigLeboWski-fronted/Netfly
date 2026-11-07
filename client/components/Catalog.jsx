import React, { useState } from 'react';
import { imageUrl, itemRoute, mediaType, personRole } from '../api/tmdb.js';

export function RouteLink({ item, onNavigate, children, ...props }) {
  const route = itemRoute(item);
  return <a {...props} href={route.href} onClick={event => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    onNavigate(route.view, route.opts);
  }}>{children}</a>;
}

function Picture({ src, alt, label }) {
  const [failed, setFailed] = useState(!src);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(false);
  return <div className="searchPoster">
    {src && <img alt={alt} loading={attempt ? 'eager' : 'lazy'}
      src={src + (attempt ? '?retry=' + attempt : '')}
      style={{ visibility: failed ? 'hidden' : undefined }}
      onError={() => { setFailed(true); setLoading(false); }}
      onLoad={() => { setFailed(false); setLoading(false); }} />}
    {failed && <div className="searchPosterFallback">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="m3 17 5-5 4 4 3-3 6 6"/></svg>
      <span>{label}</span>
      {src && <button type="button" disabled={loading} onClick={() => { setLoading(true); setAttempt(Date.now()); }}>{loading ? 'Загрузка…' : '↻ Повторить'}</button>}
    </div>}
  </div>;
}
export function CatalogImage(props) { return <Picture key={props.src || 'empty'} {...props} />; }

export function CatalogCard({ item, onNavigate }) {
  const title = item.title || item.name || 'Без названия';
  const person = mediaType(item) === 'person';
  return <article className="searchMovieCard catalogCard">
    <CatalogImage src={imageUrl(item.poster_path || item.profile_path)} alt={title} label={person ? 'Нет фото' : 'Нет постера'} />
    <RouteLink item={item} onNavigate={onNavigate} className="catalogLink">
      <strong title={title}>{title}</strong>
      <span className="small">{person ? personRole(item.known_for_department) : (item.release_date || item.first_air_date || '').slice(0, 4) || '—'}</span>
      {(item.job || item.character) && <span className="small">{item.job || item.character}</span>}
    </RouteLink>
  </article>;
}

export function ResourceStatus({ resource }) {
  return resource.error
    ? <div className="resourceStatus" role="alert"><p>{resource.error}</p><button type="button" onClick={resource.retry}>Повторить</button></div>
    : <p className="resourceStatus" role="status">Загрузка…</p>;
}
