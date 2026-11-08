export async function accountRequest(path, options = {}) {
  const response=await fetch(path,{credentials:'include',...options,headers:{'Content-Type':'application/json',...options.headers}});
  const data=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(data.error || response.statusText || 'Ошибка запроса');
  return data;
}
