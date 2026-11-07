import React from 'react';
import { imageUrl } from '../api/tmdb.js';
import { useResource } from '../hooks/useResource.js';
import { CatalogCard, CatalogImage, ResourceStatus, RouteLink } from '../components/Catalog.jsx';

export function Movie({ id, type, library, onNavigate, onAction }) {
  const resource = useResource('/api/tmdb/' + type + '/' + encodeURIComponent(id));
  if (resource.loading || resource.error) return <ResourceStatus resource={resource} />;
  const movie = resource.data;
  const title = movie.title || movie.name || 'Без названия';
  const year = (movie.release_date || movie.first_air_date || '').slice(0, 4);
  const runtime = movie.runtime || movie.episode_run_time?.[0];
  const rating = Number.isFinite(movie.vote_average) ? movie.vote_average.toFixed(1) : '—';
  const cast = (movie.credits?.cast || []).slice(0, 10);
  const director = movie.credits?.crew?.find(person => person.job === 'Director');
  const trailer = movie.videos?.results?.find(video => video.site === 'YouTube' && video.type === 'Trailer');
  const similar = (movie.similar?.results || []).slice(0, 6);
  const matching = library.filter(entry => {
    if (entry.omdb?.tmdbId) return String(entry.omdb.tmdbId) === String(id) && (entry.omdb.mediaType || (entry.omdb.type === 'series' ? 'tv' : 'movie')) === type;
    if (entry.omdb?.imdbID && movie.external_ids?.imdb_id) return entry.omdb.imdbID === movie.external_ids.imdb_id;
    return entry.name?.trim().toLowerCase() === title.trim().toLowerCase() && (!entry.year || String(entry.year) === year);
  });
  const personal = matching.find(entry => (entry.status || 'watched') === 'watched');
  const queued = matching.some(entry => entry.status === 'wish');
  return <>
    <div className="movieHero">
      {movie.backdrop_path && <div className="movieHeroBackdrop" style={{ backgroundImage: 'url("' + imageUrl(movie.backdrop_path, 'original') + '")' }} />}
      <div className="movieHeroShade" />
      <div className="movieHeroContent reactMovieHero">
        <div className="movieHeroPoster"><CatalogImage src={imageUrl(movie.poster_path, 'w500')} alt={title} label="Нет постера" /></div>
        <div className="movieHeroInfo">
          <h1>{title}</h1>
          {(movie.original_title || movie.original_name) !== title && <p className="small">{movie.original_title || movie.original_name}</p>}
          <div className="catalogActions">
            {year && <span className="tagPill">{year}</span>}
            {!!runtime && <span className="tagPill">{runtime} мин</span>}
            <span className="tagPill">⭐ {rating} ({movie.vote_count || 0})</span>
          </div>
          <p className="small">{(movie.genres || []).map(genre => genre.name).join(', ')}</p>
          <p className="movieOverview">{movie.overview || 'Описание отсутствует'}</p>
          {director && <p><strong>Режиссёр: </strong><RouteLink item={{ ...director, media_type: 'person' }} onNavigate={onNavigate}>{director.name}</RouteLink></p>}
          {!!movie.budget && <p>Бюджет: ${(movie.budget / 1000000).toFixed(1)}M</p>}
          {!!movie.revenue && <p>Сборы: ${(movie.revenue / 1000000).toFixed(1)}M</p>}
          <div className="catalogActions">
            {!personal && <button id="rateMovieBtn" type="button" className="primary" onClick={() => onAction(movie, type, 'rate')}>⭐ Оценить {type === 'tv' ? 'сериал' : 'фильм'}</button>}
            {queued ? <span className="tagPill">✓ В очереди</span> : <button id="movieAddWishBtn" type="button" onClick={() => onAction(movie, type, 'wish')}>+ В буду смотреть</button>}
          </div>
          <div className="moviePersonalRating"><div className="homeDashLabel">Моя оценка</div>{personal ? <strong>{personal.formattedScore}</strong> : <div className="homeDashMeta">Ты ещё не оценивал этот фильм.</div>}</div>
        </div>
      </div>
    </div>
    {!!cast.length && <section className="card moviePageSection"><h3>Актёры</h3><div className="movieCastGrid reactCastGrid">
      {cast.map(actor => <CatalogCard key={actor.id} item={{ ...actor, media_type: 'person' }} onNavigate={onNavigate} />)}
    </div></section>}
    {trailer && <section className="card moviePageSection"><h3>Трейлер</h3><div className="trailerFrame">
      <iframe title={'Трейлер: ' + title} src={'https://www.youtube.com/embed/' + encodeURIComponent(trailer.key)} allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowFullScreen />
    </div></section>}
    {!!similar.length && <section className="card moviePageSection"><h3>Похожие фильмы</h3><div className="movieSimilarGrid">
      {similar.map(item => <CatalogCard key={item.id} item={{ ...item, media_type: type }} onNavigate={onNavigate} />)}
    </div></section>}
  </>;
}
