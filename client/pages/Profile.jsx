import React, { useState } from 'react';

export function ProfileMovieList({ movies, onOpen }) {
  if (!movies.length) return <p className="small">Пока пусто.</p>;
  return movies.map(movie => <button type="button" className="miniItem profileMovieButton" key={movie.id} onClick={() => onOpen(movie.id)}>
    <span className="miniThumb">{movie.omdb?.posterUrl ? <img src={movie.omdb.posterUrl} alt={movie.name} loading="lazy" /> : '—'}</span>
    <span className="miniTxt"><span className="miniTitle">{movie.name || 'Без названия'}</span><span className="miniMeta"><span className="badgeRed">{movie.formattedScore}</span><span>{movie.year || '—'}</span></span></span>
  </button>);
}

export function ProfileTagline({ value, onChange }) {
  return <><label className="small" htmlFor="profileTaglineInput">Фраза профиля</label><input id="profileTaglineInput" type="text" maxLength={80} value={value || ''} placeholder="Например: Люблю медленные драмы и сильные финалы" onChange={event => onChange(event.target.value)} /></>;
}

export function ProfileFavorite({ title, movie, name, candidates = [], films = [], people = false, onChoose, onClear, onOpen }) {
  const [choosing, setChoosing] = useState(false);
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState(false);
  const score = item => (['overall','engage','emotions'].reduce((sum,key) => sum + Math.max(0, Math.min(10, Number(item.scores?.[key] || 0))),0)/3).toFixed(1);
  const selected = people ? name : movie?.name;
  const choose = value => { onChoose(value); setChoosing(false); setQuery(''); };
  return <><div className="h"><div><p className="t">{title}</p><div className="s">Это витрина твоего вкуса</div></div></div>
    {selected ? <>
      {movie ? <div className="favMovieRow"><div className="favPoster">{movie.omdb?.posterUrl ? <img src={movie.omdb.posterUrl} alt={movie.name} loading="lazy" /> : 'Нет постера'}</div><div className="favMeta"><p className="favName">{movie.name}</p><div className="favScoreRow"><span>{movie.year}</span><span className="badgeRed">{score(movie)}</span></div><p className="small">{movie.omdb?.genre}</p><button type="button" onClick={() => onOpen(movie.id)}>Открыть оценку</button></div></div> : <><p className="favName">{name}</p><div className="favStats"><span className="favStat">Фильмов: <b>{films.length}</b></span><span className="favStat">Средняя: <b>{films.length ? (films.reduce((sum,item) => sum + Number(score(item)),0)/films.length).toFixed(1) : '—'}</b></span></div><button type="button" onClick={() => setExpanded(value => !value)}>{expanded ? 'Скрыть фильмы' : 'Показать фильмы'}</button>{expanded && <div className="seriesPickerList">{films.map(item => <button type="button" key={item.id} onClick={() => onOpen(item.id)}>{item.name}</button>)}</div>}</>}
      <div className="btns"><button type="button" onClick={() => setChoosing(true)}>Сменить</button><button type="button" className="danger" onClick={onClear}>Сбросить</button></div>
    </> : <div className="favEmpty"><p>Пока не выбрано</p><button type="button" className="primary" onClick={() => setChoosing(true)}>Выбрать из оценённых</button></div>}
    {choosing && <div className="textBlock"><input type="search" aria-label={`Поиск: ${title}`} placeholder="Начни вводить…" value={query} onChange={event => setQuery(event.target.value)} /><div className="seriesPickerList">{candidates.filter(item => item.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())).map(item => <button type="button" key={item.id} onClick={() => choose(item.id)}>{item.name}</button>)}{!candidates.length && <p className="small">В оценённых пока нет подходящих вариантов.</p>}</div><button type="button" onClick={() => setChoosing(false)}>Отмена</button></div>}
  </>;
}

export function ProfileDeepStats({ movies, formatMinutes }) {
  const years = {}, groups = { 'Любимые жанры': {}, 'Любимые актёры': {}, 'Фильмы по странам': {} };
  let minutes = 0;
  for (const movie of movies) {
    const year = movie.year || 'Без года';
    const score = ['overall', 'engage', 'emotions'].reduce((sum, key) => sum + Math.max(0, Math.min(10, Number(movie.scores?.[key] || 0))), 0) / 3;
    years[year] ||= { sum: 0, count: 0 }; years[year].sum += score; years[year].count++;
    minutes += parseInt(String(movie.omdb?.runtime || '').match(/\d+/)?.[0] || '0', 10);
    const split = value => String(value || '').split(',').map(x => x.trim()).filter(Boolean);
    for (const [label, values] of [['Любимые жанры', split(movie.omdb?.genre)], ['Любимые актёры', movie.omdb?.actors || []], ['Фильмы по странам', split(movie.omdb?.country)]]) {
      for (const value of values) groups[label][value] = (groups[label][value] || 0) + 1;
    }
  }
  return <><div className="secHead"><h3>Расширенная статистика</h3><div className="small">По твоей библиотеке</div></div><div className="favStats"><div className="favStat">Просмотрено: <b>{movies.length}</b></div><div className="favStat">Время просмотра: <b>{formatMinutes(minutes)}</b></div></div>
    {Object.entries(groups).map(([label, counts]) => <div className="textBlock" key={label}><div className="k">{label}</div><div className="tagsInline">{Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0,5).map(([name,count]) => <span className="chip" key={name}>{name} <b>×{count}</b></span>)}{!Object.keys(counts).length && '—'}</div></div>)}
    <div className="textBlock"><div className="k">Средняя оценка по годам</div><div className="v">{Object.entries(years).sort((a,b) => String(a[0]).localeCompare(String(b[0]))).map(([year, data]) => `${year}: ${(data.sum/data.count).toFixed(1)}`).join(' · ') || '—'}</div></div></>;
}

export function ProfileGenres({ genres = [], selected, onToggle }) {
  if (!genres.length) return <p className="small">Пока нет жанров — добавь фильм через поиск.</p>;
  return genres.map(name => onToggle ? <button type="button" key={name} className={'genreChip isPick' + (selected?.includes(name) ? ' on' : '')} aria-pressed={!!selected?.includes(name)} onClick={() => onToggle(name)}>{name}</button> : <span key={name} className="genreChip">{name}</span>);
}

export function ProfileTiles({ tiles }) {
  return tiles.map(tile => <div className="tile" key={tile.k}><div className="n">{tile.n}</div><div className="k">{tile.k}</div></div>);
}

export function ProfileWeek({ week, time, streak, progress, goal }) {
  const pct = goal > 0 ? Math.min(100, Math.round(week.eps / goal * 100)) : 0;
  return <><div className="secHead"><h3>Просмотр за неделю</h3><div className="small">По «Смотрю сейчас»</div></div>
    <div className="favStats"><div className="favStat">За 7 дней: <b>{week.eps} серий</b></div><div className="favStat">Время: <b>{time}</b></div><div className="favStat">Стрик: <b>{streak}</b></div><div className="favStat">Текущий прогресс: <b>{progress}</b></div></div>
    {goal > 0 ? <><div className="progressBar"><div style={{ width: `${pct}%` }} /></div><p className="small">Цель недели: {week.eps}/{goal} ({pct}%)</p></> : <p className="small">Можешь поставить цель недели во вкладке «Смотрю сейчас».</p>}
  </>;
}

export function ProfileScores({ criteria, averages, insight }) {
  return <><div className="secHead"><h3>Твоя аналитика оценок</h3><div className="small">Средние по шкалам</div></div><div className="favStats">{criteria.map(item => <div className="favStat" key={item.key}>{item.label}: <b>{averages[item.key] == null ? '—' : Number(averages[item.key]).toFixed(1)}</b></div>)}</div><p className="small">{insight}</p></>;
}
