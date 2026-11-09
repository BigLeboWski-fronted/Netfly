export async function accountRequest(path, options = {}) {
  const csrf = document.cookie.match(/(?:^|; )netfly_csrf=([^;]+)/)?.[1];
  const method = (options.method || 'GET').toUpperCase();
  const headers = {'Content-Type':'application/json', ...(method !== 'GET' && csrf ? {'X-CSRF-Token': decodeURIComponent(csrf)} : {}), ...options.headers};
  const response=await fetch(path,{credentials:'include',...options,headers});
  let data;
  try { data = await response.json(); }
  catch { throw new Error('Сервер вернул некорректный ответ. Для локального входа запусти npm start.'); }
  if(!response.ok) throw new Error(data.error || response.statusText || 'Ошибка запроса');
  return data;
}
