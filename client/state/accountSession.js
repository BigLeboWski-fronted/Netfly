import { configureSession, restoreSession, setUser } from './session.js';
import { accountRequest } from '../api/account.js';

let authenticate;
export async function authenticateAccount(data) {
  if (!authenticate) throw new Error('Авторизация ещё загружается. Попробуй снова.');
  if (!data || typeof data.username !== 'string' || !data.username.trim()) {
    throw new Error('Сервер не подтвердил вход. Проверь, что запущен полный сервер приложения.');
  }
  return authenticate(data);
}

export function createAccountSession({ sync, onLoaded, target = globalThis }) {
  function anonymous() {
    sync.cancel();
    setUser(null);
  }
  async function authenticated(data) {
    target.dispatchEvent(new Event('netfly:session-ready'));
    setUser(data.username);
    try { await sync.load(); }
    catch (error) { console.warn('loadFromServer:', error.message); }
    onLoaded?.();
  }
  configureSession({ logout: async () => {
    await accountRequest('/api/logout', { method: 'POST' }).catch(() => {});
    anonymous();
  } });
  authenticate = authenticated;
  return {
    authenticated,
    restore: () => restoreSession({ request: accountRequest, onAnonymous: anonymous, onAuthenticated: authenticated }),
  };
}
