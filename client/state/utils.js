export function formatMinutes(value) {
  const minutes = Number(value || 0) || 0;
  if (minutes <= 0) return '0м';
  const hours = Math.floor(minutes / 60), rest = minutes % 60;
  return hours ? `${hours}ч${rest ? ` ${rest}м` : ''}` : `${rest}м`;
}

export function parseRuntimeMinutes(value) {
  const text = String(value || '');
  const hours = text.match(/(\d+)\s*h/i);
  const minutes = text.match(/(\d+)\s*min/i);
  if (!hours && !minutes) return null;
  const total = Number(hours?.[1] || 0) * 60 + Number(minutes?.[1] || 0);
  return total ? Math.max(1, Math.min(400, total)) : null;
}
