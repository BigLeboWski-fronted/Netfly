import React, { useEffect, useSyncExternalStore } from 'react';
import { Evaluate } from './Evaluate.jsx';
import { getEvaluationView, subscribeEvaluationView } from '../state/evaluation.js';

export function ConnectedEvaluate() {
  const view = useSyncExternalStore(subscribeEvaluationView, getEvaluationView);
  useEffect(() => {
    if (!view?.results?.length) return;
    const dismiss = event => {
      if (!document.getElementById('evaluateReactRoot')?.contains(event.target)) view.onDismiss();
    };
    document.addEventListener('click', dismiss);
    return () => document.removeEventListener('click', dismiss);
  }, [view]);
  return view ? <Evaluate {...view} /> : null;
}
