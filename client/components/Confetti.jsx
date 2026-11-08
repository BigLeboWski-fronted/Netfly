import React, { useEffect, useState } from 'react';

const listeners = new Set();
export function launchConfetti() { listeners.forEach(listener => listener()); }

export function Confetti() {
  const [pieces, setPieces] = useState([]);
  useEffect(() => {
    let active = false;
    let timer;
    const launch = () => {
      if (active) return;
      active = true;
      const colors = ['#ffffff', '#f0f0f0', '#d7d7d7', '#bdbdbd'];
      let end = 0;
      const next = Array.from({ length: 70 }, (_, index) => {
        const size = Math.random() * 6 + 6;
        const delay = Math.random() * 0.8;
        const duration = Math.random() * 1.8 + 2.4;
        end = Math.max(end, delay + duration);
        return { width: `${size}px`, height: `${size * 1.6}px`, left: `${Math.random() * 100}%`, background: colors[index % colors.length], '--delay': `${delay}s`, '--duration': `${duration}s`, '--drift': `${(Math.random() * 2 - 1) * 20}vw`, transform: `translate3d(0,-10vh,0) rotate(${Math.random() * 360}deg)` };
      });
      setPieces(next);
      timer = setTimeout(() => { setPieces([]); active = false; }, end * 1000 + 300);
    };
    listeners.add(launch);
    return () => { listeners.delete(launch); clearTimeout(timer); };
  }, []);
  return <div className={'confettiLayer' + (pieces.length ? ' show' : '')} aria-hidden="true">{pieces.map((style, index) => <span className="confettiPiece" key={index} style={style} />)}</div>;
}
