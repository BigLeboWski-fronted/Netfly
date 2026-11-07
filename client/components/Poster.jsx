import React, { useState } from 'react';

export function Poster({ src, title }) {
  const [failedSrc, setFailedSrc] = useState(null);
  return <div className="posterSm">
    {src && src !== failedSrc
      ? <img src={src} alt={title} loading="lazy" onError={() => setFailedSrc(src)} />
      : 'Нет постера'}
  </div>;
}
