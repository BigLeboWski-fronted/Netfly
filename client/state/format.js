export function formatMinutes(value) {
  const minutes = Number(value || 0) || 0;
  if (minutes <= 0) return '0м';
  const hours = Math.floor(minutes / 60), rest = minutes % 60;
  return hours ? `${hours}ч${rest ? ` ${rest}м` : ''}` : `${rest}м`;
}
