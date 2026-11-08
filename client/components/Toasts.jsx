import React, { useEffect, useRef, useState } from 'react';

const listeners = new Set();
let sequence = 0;
export function toast(title, subtitle = '', options = {}) {
  const item = { id: ++sequence, title, subtitle, options };
  listeners.forEach(listener => listener(item));
}

function Toast({ item, remove }) {
  const [closing, setClosing] = useState(false);
  const timer = useRef();
  const dismiss = () => setClosing(true);
  useEffect(() => {
    timer.current = setTimeout(dismiss, item.options.ttl ?? 2200);
    return () => clearTimeout(timer.current);
  }, [item]);
  useEffect(() => {
    if (!closing) return;
    const timeout = setTimeout(() => remove(item.id), 180);
    return () => clearTimeout(timeout);
  }, [closing, item.id, remove]);
  return <div className={'toast' + (closing ? ' toastOut' : '')} role="status" onMouseEnter={() => clearTimeout(timer.current)} onMouseLeave={() => { clearTimeout(timer.current); timer.current = setTimeout(dismiss, 900); }}>
    <div><div className="t">{item.title}</div>{item.subtitle && <div className="s">{item.subtitle}</div>}</div>
    <div className="actions">{item.options.actionText && <button type="button" className={'btn' + (item.options.actionRed ? ' red' : '')} onClick={() => { try { item.options.onAction?.(); } finally { dismiss(); } }}>{item.options.actionText}</button>}</div>
  </div>;
}

export function Toasts() {
  const [items, setItems] = useState([]);
  useEffect(() => {
    const receive = item => setItems(current => [...current, item]);
    listeners.add(receive);
    return () => listeners.delete(receive);
  }, []);
  return <div className="toastHost">{items.map(item => <Toast key={item.id} item={item} remove={id => setItems(current => current.filter(value => value.id !== id))} />)}</div>;
}
