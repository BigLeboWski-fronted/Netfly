const themes = ['netflix', 'cinema', 'bw'];
export function loadAppearance() {
  const stored = localStorage.getItem('netfly_theme_v1');
  return { theme: themes.includes(stored) ? stored : 'bw', cinemaNight: localStorage.getItem('netfly_cinema_night') === '1' };
}
export function applyAppearance({ theme, cinemaNight }) {
  [...themes, 'light'].forEach(name => document.body.classList.remove(`theme-${name}`));
  document.body.classList.add(`theme-${themes.includes(theme) ? theme : 'bw'}`);
  document.body.classList.toggle('cinemaNight', !!cinemaNight);
}
export function saveAppearance(value) {
  localStorage.setItem('netfly_theme_v1', value.theme);
  localStorage.setItem('netfly_cinema_night', value.cinemaNight ? '1' : '0');
  applyAppearance(value);
}
