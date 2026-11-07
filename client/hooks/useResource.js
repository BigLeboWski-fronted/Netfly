import { useEffect, useState } from 'react';
import { request } from '../api/tmdb.js';

export function useResource(url, delay = 0, revision = 0) {
  const [state, setState] = useState({ url: null, loading: true });
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    if (!url) return;
    const controller = new AbortController();
    let current = true;
    setState({ url, loading: true });
    const timer = setTimeout(() => {
      request(url, { signal: controller.signal }).then(data => {
        if (current) setState({ url, data, loading: false });
      }).catch(error => {
        if (current && error.name !== 'AbortError') setState({ url, error: error.message, loading: false });
      });
    }, delay);
    return () => { current = false; clearTimeout(timer); controller.abort(); };
  }, [url, delay, retry, revision]);
  return { ...(state.url === url ? state : { loading: true }), retry: () => setRetry(n => n + 1) };
}
