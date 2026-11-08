export function createOmdbSearch({ request, onResults, onStatus, delay=650 }) {
  let timer, generation=0;
  async function search(query) {
    clearTimeout(timer);
    const version=++generation, text=String(query || '').trim();
    onResults([]);
    if(text.length<3){onStatus('Введи минимум 3 символа, чтобы увидеть подсказки.');return;}
    onStatus('Ищу…');
    try {
      const data=await request({s:text});
      if(version!==generation)return;
      if(data.Response==='False'){onStatus(data.Error || 'Ничего не найдено.',true);return;}
      const items=Array.isArray(data.Search)?data.Search.slice(0,10):[];
      onStatus(items.length?'Выбери вариант из списка ниже':'Ничего не найдено.');onResults(items);
    }catch{if(version===generation)onStatus('Не удалось связаться с OMDb. Попробуй ещё раз.',true);}
  }
  function schedule(query){clearTimeout(timer);generation++;timer=setTimeout(()=>search(query),delay);}
  return {search,schedule,cancel(){clearTimeout(timer);generation++;}};
}
