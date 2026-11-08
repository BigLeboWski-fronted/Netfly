import { saveEvaluation, queueEvaluation } from './evaluation.js';

export function createEvaluationActions({ getDraft, onReset, onChanged, toast, navigate, onInvalid }) {
  function save() {
    let result;
    try { result = saveEvaluation(getDraft()); }
    catch (error) { toast(error.message); onInvalid?.(); return; }
    const { movie, edited } = result;
    toast(edited ? 'Оценка сохранена' : movie.status === 'wish' ? 'Добавлено в очередь' : 'Добавлено в оценённые', movie.name);
    onReset();
    onChanged();
    navigate(movie.status === 'wish' ? 'wish' : 'rated', { openId: movie.id });
    return movie;
  }
  function queue() {
    let movie;
    try {
      const { draft, metadata } = getDraft();
      movie = queueEvaluation(draft, metadata);
    } catch (error) { toast(error.message); return; }
    toast('Добавлено в очередь', movie.name);
    onChanged();
    navigate('wish', { openId: movie.id });
    return movie;
  }
  return { save, queue };
}
