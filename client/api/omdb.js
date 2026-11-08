export async function omdbRequest(params) {
  const query = new URLSearchParams(Object.entries(params).map(([key, value]) => [key, String(value)]));
  const response = await fetch(`/api/omdb?${query}`);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}
