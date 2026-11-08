import { loadLibrary, updateMovie, replaceLibrary, toggleMovieFavorite, removeMovie } from './library.js';

const kindOf = movie => ['series','tv-series'].includes(movie.omdb?.type) ? 'series' : 'movie';
export function createLibraryActions({ router, toast, onRate, onOpenPerson, confirm, confirmQueue, confirmRated }) {
  async function onDelete(id, element) {
    const movie=loadLibrary().find(item=>item.id===id);
    if(!movie || !await confirm({ title:'Удалить фильм?', message:movie.name, hint:'Фильм и его оценка будут удалены из библиотеки. Это действие нельзя отменить.' })) return;
    if(element?.isConnected && typeof element.animate==='function' && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      try { await element.animate([{opacity:1,transform:'scale(1)'},{opacity:0,transform:'scale(.96)'}],{duration:180,easing:'ease-out'}).finished; } catch {}
    }
    removeMovie(id); toast(movie.status==='wish'?'Удалено из очереди':'Удалено',movie.name);
  }
  const favorite = id => { const movie = toggleMovieFavorite(id); if(movie) toast(movie.favorite ? 'Добавлено в избранное' : 'Убрано из избранного', movie.name); };
  return {
    rated: {
      pageSize: 20, onToggleFavorite: favorite, onRate, onOpenPerson, onDelete,
      onClearAll: async () => {
        if(!loadLibrary().some(movie => (movie.status || 'watched') !== 'wish') || !await confirmRated()) return;
        replaceLibrary(current => current.filter(movie => movie.status === 'wish'));
      },
    },
    wish: {
      onToggleFavorite: favorite, onOpenPerson, onDelete,
      onReason: (id, value) => updateMovie(id, { wishReason: value }),
      onMove: id => { const movie = updateMovie(id, { status:'watched', queueOrder:null }); if(movie){ toast('Перемещено в оценённые', 'Теперь можно поставить оценку'); router.navigate('rated', {openId:id}); } },
      onReorder: (kind, ids) => {
        const order = new Map(ids.map((id,index) => [id,index+1]));
        replaceLibrary(current => current.map(movie => movie.status === 'wish' && kindOf(movie) === kind && order.has(movie.id) ? {...movie,queueOrder:order.get(movie.id)} : movie));
        toast('Порядок сохранён');
      },
      onClear: async kind => {
        if(!loadLibrary().some(movie => movie.status === 'wish' && kindOf(movie) === kind) || !await confirmQueue(kind)) return;
        replaceLibrary(current => current.filter(movie => !(movie.status === 'wish' && kindOf(movie) === kind)));
      },
      onRandom: (kind, list) => { if(!list.length){toast('Очередь пуста');return;} const movie=list[Math.floor(Math.random()*list.length)]; router.navigate('wish',{openId:movie.id});toast('Случайный выбор',movie.name); },
    },
  };
}
