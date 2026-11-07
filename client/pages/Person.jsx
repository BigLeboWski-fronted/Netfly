import React from 'react';
import { imageUrl, personRole } from '../api/tmdb.js';
import { useResource } from '../hooks/useResource.js';
import { CatalogCard, CatalogImage, ResourceStatus } from '../components/Catalog.jsx';

export function Person({ id, onNavigate }) {
  const resource = useResource('/api/tmdb/person/' + encodeURIComponent(id));
  if (resource.loading || resource.error) return <ResourceStatus resource={resource} />;
  const person = resource.data;
  const credits = [...(person.combined_credits?.cast || []), ...(person.combined_credits?.crew || [])]
    .filter(item => item.media_type === 'movie' || item.media_type === 'tv')
    .sort((a, b) => (b.popularity || 0) - (a.popularity || 0));
  const unique = [...new Map(credits.map(item => [item.media_type + ':' + item.id, item])).values()];
  return <>
    <section className="card moviePageSection"><div className="personHero reactPersonHero">
      <div className="personPortrait"><CatalogImage src={imageUrl(person.profile_path)} alt={person.name} label="Нет фото" /></div>
      <div className="personBio"><h1>{person.name}</h1><p className="small">{personRole(person.known_for_department)}</p>
        <p>{[person.birthday, person.place_of_birth].filter(Boolean).join(' · ')}</p>
        <p className="personBiography">{person.biography || 'Биография на русском пока отсутствует.'}</p>
      </div>
    </div></section>
    <section className="card moviePageSection"><h3>Фильмография</h3><div id="personFilmography" className="movieSimilarGrid">
      {unique.map(item => <CatalogCard key={item.media_type + ':' + item.id} item={item} onNavigate={onNavigate} />)}
    </div>{!unique.length && <p>Фильмография пока отсутствует.</p>}</section>
  </>;
}
