let openRating;
let applyCatalogMovie;
export function configureRatingNavigation(action) { openRating = action; }
export function configureCatalogRating(action) { applyCatalogMovie = action; }
export function requestCatalogRating(movie, type, action) {
  if (!applyCatalogMovie) throw new Error('Форма оценки ещё загружается');
  return applyCatalogMovie(movie, type, action);
}
export function requestMovieRating(movie) {
  if (!openRating) throw new Error('Форма оценки ещё загружается');
  return openRating(movie);
}
