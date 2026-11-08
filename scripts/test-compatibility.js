// Test-only adapter for fixtures that still use the former global state.
let movies = window.__netflyTest.library.loadLibrary();
let nowState = window.__netflyTest.profileStorage.getProgressSnapshot();
let omdbEpCache = window.__netflyTest.profileStorage.getEpisodeCache();
const evaluationState = window.__netflyTest.evaluationController.state;
window.__netflyTest.library.subscribeLibrary(value => { movies = value; });
window.__netflyTest.profileStorage.subscribeProgress(() => { nowState = window.__netflyTest.profileStorage.getProgressSnapshot(); });
function saveMovies() { window.__netflyTest.library.saveLibrary(movies); }
function saveNowState() { window.__netflyTest.profileStorage.saveNowState(nowState); }
function goTo(view, options = {}) { window.__netflyTest.router.navigate(view, options); }
function deleteMovie(id) { window.__netflyTest.library.removeMovie(id); }
