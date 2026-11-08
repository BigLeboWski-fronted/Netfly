export function parseRuntimeMinutes(value) {
  const text = String(value || '');
  const hours = text.match(/(\d+)\s*h/i);
  const minutes = text.match(/(\d+)\s*min/i);
  if (!hours && !minutes) return null;
  const total = Number(hours?.[1] || 0) * 60 + Number(minutes?.[1] || 0);
  return total ? Math.max(1, Math.min(400, total)) : null;
}
