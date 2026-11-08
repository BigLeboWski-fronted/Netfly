export const criteria = [{key:'overall',label:'Общее'},{key:'engage',label:'Вовлечённость'},{key:'emotions',label:'Эмоции'}];
const score = movie => criteria.reduce((sum,{key})=>sum+Math.max(0,Math.min(10,Number(movie.scores?.[key])||0)),0)/3;
export function profileData(movies) {
  const rated=movies.filter(movie=>(movie.status || 'watched')==='watched');
  const averages=Object.fromEntries(criteria.map(({key})=>[key,rated.length?rated.reduce((sum,movie)=>sum+Math.max(0,Math.min(10,Number(movie.scores?.[key])||0)),0)/rated.length:null]));
  const top=criteria.slice().sort((a,b)=>(averages[b.key] || 0)-(averages[a.key] || 0))[0].key;
  const label={overall:'общее впечатление',engage:'вовлечённость',emotions:'эмоции'}[top];
  const decorate=movie=>({...movie,formattedScore:score(movie).toFixed(1)});
  return { rated, tiles:[{k:'Оценено',n:rated.length},{k:'Буду смотреть',n:movies.filter(movie=>movie.status==='wish').length},{k:'Избранное',n:movies.filter(movie=>movie.favorite).length},{k:'Средняя оценка',n:rated.length?(rated.reduce((sum,movie)=>sum+score(movie),0)/rated.length).toFixed(1):'—'}],
    scores:{criteria,averages,insight:rated.length?`Инсайт: ты чаще всего высоко оцениваешь ${label}.`:'Добавь оценки, чтобы увидеть инсайты.'},
    allGenres:[...new Set(rated.flatMap(movie=>String(movie.omdb?.genre || movie.genre || movie.genres || movie.omdbGenre || '').split(',').map(value=>value.trim()).filter(Boolean)))].sort((a,b)=>a.localeCompare(b,'ru')).slice(0,30),
    best:rated.slice().sort((a,b)=>score(b)-score(a)).slice(0,3).map(decorate),
    recent:rated.slice().sort((a,b)=>(b.createdAt || 0)-(a.createdAt || 0)).slice(0,3).map(decorate)
  };
}
