import React, { useState } from 'react';
import { loadAppearance, saveAppearance } from '../state/appearance.js';
import { toast } from '../components/Toasts.jsx';
import { createPortal } from 'react-dom';
import { AccountUsername, AccountCredentials } from './Account.jsx';
import { accountRequest } from '../api/account.js';
import { setUser } from '../state/session.js';

export function ConnectedSettings() {
  const [accountMode, setAccountMode] = useState(null);
  const [appearance, setAppearance] = useState(loadAppearance);
  const update = patch => {
    const next = { ...appearance, ...patch };
    saveAppearance(next);
    setAppearance(next);
  };
  const close = () => setAccountMode(null);
  return <><Settings theme={appearance.theme} cinemaNight={appearance.cinemaNight} onAccount={setAccountMode}
    onTheme={theme => { update({ theme }); toast('Тема изменена'); }}
    onNight={cinemaNight => { update({ cinemaNight }); toast(cinemaNight ? 'Киноночь включена' : 'Киноночь выключена'); }} />
    {accountMode && createPortal(accountMode === 'username'
      ? <AccountUsername request={accountRequest} onClose={close} onSuccess={username => { setUser(username); toast('Имя изменено', username); }} />
      : <AccountCredentials key={accountMode} mode={accountMode} request={accountRequest} onClose={close} onSuccess={() => toast(accountMode === 'email' ? 'Email изменён' : 'Пароль изменён')} />,
      document.getElementById('accountReactRoot'))}
  </>;
}

export function Settings({ theme: initialTheme, cinemaNight: initialNight, onTheme, onNight, onAccount }) {
  const [theme, setTheme] = useState(initialTheme);
  const [night, setNight] = useState(initialNight);
  return <>
    <div className="settingsGroup"><div className="settingsRow"><div className="settingsRowLabel"><strong>Тема оформления</strong><span>Выбери настроение интерфейса</span></div>
      <select aria-label="Тема оформления" value={theme} onChange={event => { setTheme(event.target.value); onTheme(event.target.value); }}><option value="netflix">Netflix</option><option value="cinema">Кинотеатр</option><option value="bw">Чёрно-белая</option></select>
    </div></div>
    <div className="settingsGroup"><div className="settingsRow"><div className="settingsRowLabel"><strong>Киноночь</strong><span>Тёплый приглушённый режим</span></div>
      <label className="cnSwitch"><input aria-label="Киноночь" type="checkbox" checked={night} onChange={event => { setNight(event.target.checked); onNight(event.target.checked); }} /><span className="cnSlider" /></label>
    </div></div>
    <div className="settingsGroup">{[['username','Имя пользователя'],['email','Email'],['password','Пароль']].map(([kind,label]) => <div className="settingsRow" key={kind}><div className="settingsRowLabel"><strong>{label}</strong><span>Можно менять раз в 3 дня</span></div><button type="button" className="primary" aria-label={`Изменить: ${label}`} onClick={() => onAccount(kind)}>Изменить</button></div>)}</div>
  </>;
}
