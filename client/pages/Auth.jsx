import React, { useState } from 'react';

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
