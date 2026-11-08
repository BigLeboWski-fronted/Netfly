import React, { useState } from 'react';
import { Register } from './Register.jsx';
import { PasswordRecovery } from './PasswordRecovery.jsx';

export function AuthScreen({ request, onSuccess }) {
  const [mode,setMode]=useState('login');
  return <div className="authCard"><div className="authLogo">Net<span className="red">fly</span></div><div className="authSub">Твой личный трекер фильмов и сериалов</div>
    {mode !== 'forgot' && <div className="authTabs"><button type="button" className={'authTab'+(mode==='login'?' active':'')} onClick={()=>setMode('login')}>Войти</button><button type="button" className={'authTab'+(mode==='register'?' active':'')} onClick={()=>setMode('register')}>Регистрация</button></div>}
    {mode==='login'?<Login request={request} onSuccess={onSuccess}/>:mode==='register'?<Register request={request} onSuccess={onSuccess}/>:<PasswordRecovery request={request} onDone={()=>setMode('login')}/>}
    {mode==='login'&&<button type="button" className="authForgotLink" onClick={()=>setMode('forgot')}>Забыл пароль</button>}
  </div>;
}

export function Login({ request, onSuccess }) {
  const [email, setEmail] = useState(''), [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); if(busy) return;
    setBusy(true); setError('');
    try {
      const data = await request('/api/login', { method:'POST', body:JSON.stringify({ email:email.trim(), password }) });
      await onSuccess(data); setPassword('');
    } catch(error) { setError(error.message); } finally { setBusy(false); }
  }
  return <form className="authFields" onSubmit={submit}>
    <div><label htmlFor="authEmail">Email или имя пользователя</label><input id="authEmail" required maxLength={80} autoComplete="username" placeholder="you@example.com" value={email} disabled={busy} onChange={event => setEmail(event.target.value)} /></div>
    <div><label htmlFor="authPassword">Пароль</label><input id="authPassword" type="password" required maxLength={72} autoComplete="current-password" placeholder="••••••" value={password} disabled={busy} onChange={event => setPassword(event.target.value)} /></div>
    {error && <p className="authError" role="alert">{error}</p>}
    <button className="authSubmit" type="submit" disabled={busy}>{busy ? 'Входим…' : 'Войти'}</button>
  </form>;
}
