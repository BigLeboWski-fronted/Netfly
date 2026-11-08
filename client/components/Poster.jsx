import React, { useEffect, useState } from 'react';

export function Poster({ src, title }) {
  const [failedSrc, setFailedSrc] = useState(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const retry = () => { setFailedSrc(null); setAttempt(Date.now()); };
    window.addEventListener('netfly:session-ready', retry);
    return () => window.removeEventListener('netfly:session-ready', retry);
  }, []);
  return <div className="posterSm">
    {src && src !== failedSrc
      ? <img src={src + (attempt ? `${src.includes('?') ? '&' : '?'}retry=${attempt}` : '')} alt={title} loading="lazy" onError={() => setFailedSrc(src)} />
      : 'Нет постера'}
  </div>;
}
