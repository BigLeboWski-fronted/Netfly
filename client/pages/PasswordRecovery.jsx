import React, { useState } from 'react';

export function PasswordRecovery({ request, onDone }) {
  const [email, setEmail] = useState(''), [code, setCode] = useState(''), [password, setPassword] = useState('');
  const [sent, setSent] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); if(busy) return; setBusy(true); setError('');
    try {
      await request(sent ? '/api/reset-password' : '/api/forgot-password', { method:'POST', body:JSON.stringify(sent ? {email:email.trim(), code:code.trim(), password} : {email:email.trim()}) });
      if(sent){ setCode(''); setPassword(''); setSent(false); onDone(); } else setSent(true);
    } catch(error) { setError(error.message); } finally { setBusy(false); }
  }
  return <form className="authFields passwordRecovery" onSubmit={submit}><fieldset disabled={busy} className="authReactFields">
    <div className="recoveryHeading"><span className="recoveryStep">{sent ? 'ШАГ 2 ИЗ 2' : 'ШАГ 1 ИЗ 2'}</span><h2>{sent ? 'Новый пароль' : 'Восстановить доступ'}</h2><p>{sent ? 'Введи код из письма и придумай новый пароль.' : 'Укажи почту своего аккаунта — отправим код для смены пароля.'}</p></div>
    {sent ? <><p className="small">Код отправлен на {email}</p><div><label htmlFor="recoveryCode">Код из письма</label><input id="recoveryCode" required maxLength={6} autoComplete="one-time-code" value={code} onChange={event=>setCode(event.target.value)} /></div><div><label htmlFor="recoveryPassword">Новый пароль</label><input id="recoveryPassword" type="password" required minLength={6} maxLength={72} autoComplete="new-password" value={password} onChange={event=>setPassword(event.target.value)} /></div></> : <div><label htmlFor="recoveryEmail">Email</label><input id="recoveryEmail" type="email" required autoComplete="email" value={email} onChange={event=>setEmail(event.target.value)} /></div>}
    {error && <p className="authError" role="alert">{error}</p>}
    <button type="submit" className="authSubmit">{busy?'Подождите…':sent?'Сменить пароль':'Отправить код'}</button>
    {sent && <button type="button" onClick={()=>{setSent(false);setError('');}}>Изменить email</button>}
    <button type="button" className="recoveryBack" onClick={onDone}>← Вернуться ко входу</button>
  </fieldset></form>;
}
