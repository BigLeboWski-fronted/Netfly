import React, { useEffect, useRef, useState } from 'react';
import { useResource } from '../hooks/useResource.js';

const expandedSeasons = new Map();

function SeriesDialog({ title, children, onClose }) {
  const ref = useRef(null);
  useEffect(() => { ref.current.showModal(); }, []);
  return <dialog className="deleteConfirm seriesDialog" ref={ref} onCancel={event => { event.preventDefault(); onClose(); }} onClick={event => { if(event.target === ref.current) onClose(); }}>
    <h3>{title}</h3>{children}<button type="button" onClick={onClose}>Отмена</button>
  </dialog>;
}

export function SeriesControls({ active, next, finished, queue = [], onReveal, onPick, onRemove, onRate, onDismiss }) {
  const [picking, setPicking] = useState(false);
  const [query, setQuery] = useState('');
  return <div className="seriesControls">
    {next && <button type="button" className="nextBanner" onClick={onReveal}>Следующая: S{String(next.season).padStart(2, '0')}E{String(next.episode).padStart(2, '0')}{next.title ? ` — ${next.title}` : ''}</button>}
    {finished && <div className="finishPrompt"><div className="finishTitle">Сериал досмотрен 🎬</div><p className="finishSubtitle">Все серии отмечены. Можно поставить оценку.</p><div className="finishActions"><button type="button" className="primary" onClick={onRate}>Оценить сериал</button><button type="button" onClick={onDismiss}>Позже</button></div></div>}
    {active ? <><button type="button" className="danger" onClick={onRemove}>Убрать из «Смотрю сейчас»</button><p className="small">Сериал останется в очереди.</p></> : <><p className="small">Выбери сериал из раздела «Буду смотреть».</p><button type="button" className="primary" onClick={() => { setQuery(''); setPicking(true); }}>Выбрать из очереди</button></>}
    {picking && <SeriesDialog title="Выбрать сериал" onClose={() => setPicking(false)}>
      <input aria-label="Поиск сериала в очереди" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Название сериала" />
      <div className="seriesPickerList">{queue.filter(movie => String(movie.name || '').toLocaleLowerCase().includes(query.toLocaleLowerCase())).map(movie => <button type="button" key={movie.id} onClick={() => { setPicking(false); onPick(movie.id); }}>{movie.name}{movie.year ? ` · ${movie.year}` : ''}</button>)}{!queue.length && <p>В очереди пока нет сериалов.</p>}</div>
    </SeriesDialog>}
  </div>;
}

function NumberControl({ value, min, max, label, onChange }) {
  const commit = number => onChange(Math.max(min, Math.min(max, number)));
  return <span className="seriesNumberControl">
    <input aria-label={label} type="number" min={min} max={max} value={value} onChange={event => event.target.value === '' ? onChange('') : commit(Number(event.target.value))} />
    <span className="seriesNumberButtons">
      <button type="button" aria-label={`${label}: уменьшить`} disabled={Number(value) <= min} onClick={() => commit(Number(value || 0) - 1)}>−</button>
      <button type="button" aria-label={`${label}: увеличить`} disabled={Number(value) >= max} onClick={() => commit(Number(value || 0) + 1)}>+</button>
    </span>
  </span>;
}

export function SeriesEpisodes({ seriesId, seasons = {}, watched = {}, onToggle }) {
  const [opened, setOpened] = useState(() => expandedSeasons.get(seriesId) || {});
  useEffect(() => {
    const reveal = event => {
      setOpened(value => {
        const next = { ...value, [event.detail.season]: true };
        expandedSeasons.set(seriesId, next);
        return next;
      });
    };
    window.addEventListener('netfly:reveal-episode', reveal);
    return () => window.removeEventListener('netfly:reveal-episode', reveal);
  }, [seriesId]);
  const numbers = Object.keys(seasons).map(Number).filter(n => n > 0).sort((a, b) => a - b);
  if (!numbers.length) return <p className="small">Не удалось получить список серий из OMDb.</p>;
  return numbers.map(season => <div key={season} data-season={season} className={'seasonBlock' + (opened[season] ? ' open' : '')}>
    <button type="button" className="seasonHead" aria-expanded={!!opened[season]} onClick={() => setOpened(value => {
      const next = { ...value, [season]: !value[season] };
      expandedSeasons.set(seriesId, next);
      return next;
    })}>
      <b>Сезон {season}</b><span className="chip">{seasons[season].filter(ep => watched[`S${season}E${ep.Episode}`]).length}/{seasons[season].length}</span>
    </button>
    <div className="seasonBody">{seasons[season].map(ep => {
      const key = `S${season}E${ep.Episode}`;
      return <div className="epRow" data-key={key} key={key}><label className="epLeft">
        <input className="episodeCheckbox" aria-label={`Сезон ${season}, серия ${ep.Episode}: просмотрено`} type="checkbox" checked={!!watched[key]} onChange={event => onToggle(key, event.target.checked)} />
        <span className="epMeta"><span className="epTitle">E{ep.Episode} • {ep.Title || 'Серия'}</span><span className="epSub">{[ep.Released !== 'N/A' && ep.Released, ep.imdbRating !== 'N/A' && ep.imdbRating && `IMDb: ${ep.imdbRating}`].filter(Boolean).join(' • ') || '—'}</span></span>
      </label><span className="epBadge">{watched[key] ? 'Просмотрено' : '—'}</span></div>;
    })}</div>
  </div>);
}

export function SeriesCalendar({ imdbId, tmdbId }) {
  const params = new URLSearchParams({imdb:imdbId || ''});
  if(tmdbId) params.set('id',tmdbId);
  const resource = useResource(imdbId ? `/api/tmdb/calendar?${params}` : null);
  if(!imdbId) return null;
  const data=resource.data || {}, episode=data.next;
  let description=data.status==='Ended'?'Сериал завершён.':data.status==='Canceled'?'Сериал закрыт.':'Дата следующей серии пока не объявлена.';
  if(episode?.air_date){
    const date=new Date(episode.air_date+'T12:00:00');
    if(Number.isFinite(date.getTime())) description=`Сезон ${episode.season_number} · Серия ${episode.episode_number} · ${date.toLocaleDateString('ru-RU',{day:'numeric',month:'long',year:'numeric'})}`;
  }
  return <><h3>Календарь серий</h3>{resource.loading ? <p className="small" role="status">Загружаю даты…</p> : resource.error ? <div role="alert"><p className="small">{resource.error}</p><button type="button" onClick={resource.retry}>Повторить</button></div> : <p className="small" title="Дата оригинального выхода по TMDB. Выход озвучки может отличаться.">{description}</p>}</>;
}

export function SeriesHomeWidget({ state, progress, next, weeks, onOpen, onNext }) {
  if (!state.imdbID) return null;
  const { watched, total, pct } = progress;
  const remaining = total == null ? null : Math.max(0, total - watched);
  return <section className="card" style={{ marginTop: 12 }}><div className="nowWidget">
    <div className="posterSm" style={{ width: 74, height: 110 }}>{state.posterUrl ? <img src={state.posterUrl} alt={state.title || 'Сериал'} loading="lazy" /> : '—'}</div>
    <div className="nowWidgetMain"><div className="nowWidgetHead">
      <div style={{ minWidth: 0 }}><p className="nowTitle">Смотрю сейчас: {state.title || 'Сериал'}</p>
        <div className="nowSub">{total ? `Прогресс: ${watched}/${total} (${pct || 0}%)` : `Отмечено серий: ${watched}`}</div>
        <div className="nowMiniStats">
          {remaining != null && <div>Осталось серий: <b>{remaining}</b></div>}
          {remaining != null && state.runtimeMin > 0 && <div>≈ {Math.round(remaining * state.runtimeMin / 60)} ч</div>}
          {weeks != null && <div>Недель просмотра: {weeks}</div>}
        </div>
      </div>
      <div className="btns"><button type="button" onClick={onOpen}>Открыть</button><button type="button" className="primary" disabled={!next} onClick={onNext}>Следующая серия</button></div>
    </div><div className="progressBar" role="progressbar" aria-label="Прогресс просмотра" aria-valuenow={Math.min(100, pct || 0)} aria-valuemin={0} aria-valuemax={100}><div style={{ width: `${Math.min(100, pct || 0)}%` }} /></div></div>
  </div></section>;
}

export function SeriesProgress({ state, progress, next, onNext, onSettings, onReset, children }) {
  const [confirmReset, setConfirmReset] = useState(false);
  const { watched, total, pct } = progress;
  if (!state.imdbID) return <div className="nowEmpty">Пока ничего не выбрано. Выбери сериал из очереди.</div>;
  return <>
    <div className="posterBig">
      <div className="posterBigImg" style={{ width: 110, height: 165 }}>{state.posterUrl ? <img src={state.posterUrl} alt={state.title || 'Сериал'} /> : 'Нет постера'}</div>
      <div className="posterMeta">
        <div className="nowWidgetHead"><div><p className="nowTitle">{state.title || 'Сериал'}</p><div className="nowSub">{total ? `Прогресс: ${watched}/${total} (${pct || 0}%)` : `Отмечено серий: ${watched}`}</div></div></div>
        <div className="progressBar" role="progressbar" aria-label="Прогресс просмотра" aria-valuenow={pct || 0} aria-valuemin={0} aria-valuemax={100}><div style={{ width: `${Math.min(100, pct || 0)}%` }} /></div>
        <button type="button" className="primary" disabled={!next} onClick={onNext}>Следующая серия{next ? ` · S${next.season} E${next.episode}` : ''}</button>
        <details className="nowPreferences"><summary>Настройки и статистика просмотра</summary>
          {total != null && <p className="small">Осталось серий: {Math.max(0, total - watched)}{state.runtimeMin ? ` · ≈ ${Math.round(Math.max(0, total - watched) * state.runtimeMin / 60)} ч` : ''}</p>}
          <div className="inline">
            <label>Мин/серия <NumberControl label="Минут на серию" min={1} max={400} value={state.runtimeMin || ''} onChange={value => onSettings({ runtimeMin: value === '' ? null : value })} /></label>
            <label>Стрик <input type="checkbox" checked={!!state.streakOn} onChange={e => onSettings({ streakOn: e.target.checked })} /></label>
            <label>Цель недели (серий) <NumberControl label="Цель недели" min={0} max={99} value={state.goalEps || 0} onChange={value => onSettings({ goalEps: value === '' ? 0 : value })} /></label>
          </div><button type="button" className="danger" onClick={() => setConfirmReset(true)}>Сбросить прогресс</button>
        </details>
      </div>
    </div>
    <div id="nowEpisodes" className="episodeGrid">{children}</div>
    {confirmReset && <SeriesDialog title="Сбросить прогресс?" onClose={() => setConfirmReset(false)}><p>Отметки просмотренных серий, история просмотра и стрик будут очищены. Это действие нельзя отменить.</p><button type="button" className="danger" onClick={() => { setConfirmReset(false); onReset(); }}>Сбросить прогресс</button></SeriesDialog>}
  </>;
}
