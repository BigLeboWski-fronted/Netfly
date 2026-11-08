import React, { useEffect, useRef } from 'react';
export function Confirmation({ title, message, hint, confirmLabel = 'Удалить', onResolve }) {
  const ref = useRef(null);
  useEffect(() => { ref.current.showModal(); }, []);
  return <dialog ref={ref} className="deleteConfirm" aria-labelledby="confirmation-title" onCancel={event => { event.preventDefault(); onResolve(false); }} onClick={event => {
    if(event.target !== ref.current) return;
    const rect=ref.current.getBoundingClientRect();
    if(event.clientX<rect.left || event.clientX>rect.right || event.clientY<rect.top || event.clientY>rect.bottom) onResolve(false);
  }}><h3 id="confirmation-title">{title}</h3><p className="deleteConfirmName">{message}</p><p className="deleteConfirmHint">{hint}</p><div className="deleteConfirmActions"><button type="button" autoFocus onClick={()=>onResolve(false)}>Отмена</button><button type="button" className="danger" onClick={()=>onResolve(true)}>{confirmLabel}</button></div></dialog>;
}
