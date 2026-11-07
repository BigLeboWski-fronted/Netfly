export async function request(path, { signal } = {}) {
  const response = await fetch(path, { credentials: 'include', signal });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Не удалось загрузить данные');
  return data;
}
export const imageUrl = (path, size = 'w300') => path ? '/api/tmdb/image/' + size + path : null;
export const mediaType = item => item.media_type || (item.title ? 'movie' : 'tv');
export const personRole = value => ({ Acting: 'Актёр', Directing: 'Режиссёр' }[value] || value || 'Персона');
export function itemRoute(item) {
  return mediaType(item) === 'person'
    ? { view: 'person', opts: { personId: item.id }, href: '/person/' + item.id }
    : { view: 'movie', opts: { tmdbId: item.id, type: mediaType(item) }, href: '/movie/' + item.id + '?type=' + mediaType(item) };
}
