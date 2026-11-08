export async function accountRequest(path, options = {}) {
  const response=await fetch(path,{credentials:'include',...options,headers:{'Content-Type':'application/json',...options.headers}});
  let data;
  try { data = await response.json(); }
  catch { throw new Error('Сервер вернул некорректный ответ. Для локального входа запусти npm start.'); }
  if(!response.ok) throw new Error(data.error || response.statusText || 'Ошибка запроса');
  return data;
}
