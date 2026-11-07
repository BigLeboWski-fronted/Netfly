import React, { useEffect, useRef, useState } from 'react';
const criteria=[['overall','Общее впечатление'],['engage','Вовлечённость'],['emotions','Эмоции после просмотра']];
function ScoreSlider({ id, value, onChange }) {
  const [raw,setRaw]=useState(value);
  const dragging=useRef(false);
  useEffect(()=>{if(!dragging.current)setRaw(value);},[value]);
  const snap=()=>{dragging.current=false;setRaw(Math.round(raw));};
  return <input id={id} type="range" className="scoreRange" min={0} max={10} step={.01} value={raw} style={{'--p':`${raw*10}%`}} onPointerDown={()=>{dragging.current=true;}} onChange={event=>{const next=Number(event.target.value);setRaw(next);onChange(Math.round(next));}} onPointerUp={snap} onPointerCancel={snap} onKeyUp={snap} onBlur={snap} />;
}
export function Evaluate({initial,revision,results,message,onChange,onSave,onWish,onSearch,onSelect}){
  const [form,setForm]=useState(initial);
  useEffect(()=>setForm(initial),[revision]);
  const change=(key,value)=>{setForm(v=>({...v,[key]:value}));onChange(key,value);};
  const field=(key,label,type='text')=><div><label htmlFor={`evaluate-${key}`}>{label}</label><input id={`evaluate-${key}`} type={type} value={form[key]??''} onChange={e=>change(key,e.target.value)}/></div>;
  const sum=criteria.reduce((n,[key])=>n+Number(form.scores[key]||0),0);
  return <form className="card evaluateReact" onSubmit={e=>{e.preventDefault();onSave();}}>
    <label htmlFor="evaluate-name">Название фильма / сериала</label><div className="nameRow"><input id="evaluate-name" required maxLength={80} value={form.name} placeholder="Название фильма или сериала" onChange={e=>change('name',e.target.value)}/><button type="button" onClick={onSearch}>Найти</button><button type="button" onClick={onWish}>+ В буду смотреть</button></div>
    {!!results.length&&<div className="evaluateResults">{results.map(item=><button type="button" className="resItem" key={item.imdbID} onClick={()=>onSelect(item.imdbID)}><span className="miniThumb">{item.Poster&&item.Poster!=='N/A'?<img src={item.Poster} alt={item.Title}/>: '—'}</span><span>{item.Title} · {item.Year}</span></button>)}</div>}
    <p className="omdbHint" aria-live="polite">{message}</p>
    <div className="formGrid">{field('director','Режиссёр(ы)')}{field('year','Год','number')}</div>
    <div className="formGrid2"><div><label htmlFor="evaluate-status">Статус</label><select id="evaluate-status" value={form.status} onChange={e=>change('status',e.target.value)}>{[['watched','Оценено'],['wish','Буду смотреть'],['rewatch','Пересматриваю'],['dropped','Бросил']].map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></div>{field('tags','Теги (через запятую)')}</div>
    <label htmlFor="evaluate-notes">Заметки</label><textarea id="evaluate-notes" value={form.notes} onChange={e=>change('notes',e.target.value)}/>
    <div className="rows">{criteria.map(([key,label])=><div className="row" key={key}><div className="rowTop"><label className="rowTitle" htmlFor={`score-${key}`}>{label}</label><span className="valuePill">{form.scores[key]}</span></div><ScoreSlider id={`score-${key}`} value={form.scores[key]} onChange={value=>change('scores',{...form.scores,[key]:value})}/></div>)}</div>
    <div className="summary"><div className="scoreBox"><div className="score"><div className="k">Итоговая оценка</div><div className="v">{(sum/3).toFixed(1)}</div></div><div className="score"><div className="k">Сумма (3 шкалы)</div><div className="v">{sum}</div></div></div><div className="btns"><button type="button" onClick={()=>change('scores',{overall:0,engage:0,emotions:0})}>Сбросить</button><button type="submit" className="primary">{initial.editing?'Сохранить оценку':'Добавить'}</button></div></div>
    <p className="note">Итоговая оценка — среднее трёх шкал от 0 до 10.</p>
  </form>;
}
