import React, { useEffect, useRef, useState } from 'react';

export function AccountCredentials({ mode, request, onClose, onSuccess }) {
  const ref = useRef(null);
  const [values, setValues] = useState({});
  const [codeMode, setCodeMode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => { ref.current.showModal(); }, []);
  async function run(action) { setBusy(true); setError(''); try { await action(); } catch(error) { setError(error.message); } finally { setBusy(false); } }
  const send = () => run(async () => {
    await request(mode === 'email' ? '/api/account/change-email/send-code' : '/api/account/send-password-code', { method:'POST' });
    setCodeMode(true);
  });
  const field = (key, label, type = 'text') => <label>{label}<input required type={type} autoComplete={type === 'password' ? (key === 'newPassword' ? 'new-password' : 'current-password') : key === 'code' ? 'one-time-code' : 'email'} minLength={key === 'newPassword' ? 6 : undefined} maxLength={key === 'code' ? 6 : type === 'password' ? 72 : 254} value={values[key] || ''} onChange={event => setValues(current => ({ ...current, [key]: event.target.value }))} /></label>;
  function submit(event) {
    event.preventDefault();
    run(async () => {
      const body = mode === 'email' ? { newEmail: values.newEmail.trim(), code: values.code.trim() } : { newPassword: values.newPassword, ...(codeMode ? { code: values.code.trim() } : { currentPassword: values.currentPassword }) };
      await request('/api/account/change-' + mode, { method:'POST', body:JSON.stringify(body) });
      onSuccess(); onClose();
    });
  }
  return <dialog ref={ref} className="deleteConfirm accountReactDialog" onCancel={event => { event.preventDefault(); if(!busy) onClose(); }}><h3>{mode === 'email' ? 'Изменить email' : 'Изменить пароль'}</h3><p className="small">Можно менять раз в 3 дня.</p><form onSubmit={submit}><fieldset disabled={busy}>
    {mode === 'email' ? codeMode ? <><p className="small">Код отправлен на текущую почту.</p>{field('code','Код из письма')}{field('newEmail','Новый email','email')}</> : <button type="button" onClick={send}>Отправить код на текущую почту</button> : <>
      {codeMode ? <><p className="small">Код отправлен на твою почту.</p>{field('code','Код из письма')}</> : field('currentPassword','Текущий пароль','password')}
      {field('newPassword','Новый пароль','password')}
      <button type="button" onClick={codeMode ? () => { setCodeMode(false); setError(''); } : send}>{codeMode ? 'Использовать текущий пароль' : 'Получить код по почте'}</button>
    </>}
    {error && <p role="alert">{error}</p>}<div className="btns"><button type="button" onClick={onClose}>Отмена</button>{(mode !== 'email' || codeMode) && <button type="submit" className="primary">{busy ? 'Сохраняю…' : 'Сохранить'}</button>}</div>
  </fieldset></form></dialog>;
}
export function AccountUsername({ request, onClose, onSuccess }) {
  const ref = useRef(null);
  const [name, setName] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState('');
  useEffect(() => { ref.current.showModal(); }, []);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { await request('/api/account/change-username', { method:'POST', body:JSON.stringify({ username:name.trim() }) }); onSuccess(name.trim()); onClose(); }
    catch(error) { setError(error.message); } finally { setBusy(false); }
  }
  return <dialog ref={ref} className="deleteConfirm accountReactDialog" onCancel={event => { event.preventDefault(); if(!busy) onClose(); }}><h3>Изменить имя</h3><p className="small">Можно менять раз в 3 дня.</p><form onSubmit={submit}><label>Новое имя<input required minLength={3} maxLength={40} value={name} disabled={busy} onChange={event => setName(event.target.value)} /></label>{error && <p role="alert">{error}</p>}<div className="btns"><button type="button" disabled={busy} onClick={onClose}>Отмена</button><button type="submit" className="primary" disabled={busy}>{busy ? 'Сохраняю…' : 'Сохранить'}</button></div></form></dialog>;
}
