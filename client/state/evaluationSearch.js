import { omdbRequest } from '../api/omdb.js';
import { createOmdbSearch } from './omdbSearch.js';
import { fromOmdb } from './evaluation.js';

export function createEvaluationSearch({ onResults, onStatus, onSelected }) {
  let generation = 0;
  const search = createOmdbSearch({ request: omdbRequest, onResults, onStatus });
  async function select(id) {
    search.cancel();
    const version = ++generation;
    onStatus('Загружаю детали…');
    try {
      const data = await omdbRequest({ i: id, plot: 'short' });
      if (version !== generation) return;
      if (data.Response === 'False') {
        onStatus(data.Error || 'Не удалось получить детали.', true);
        return;
      }
      onSelected(fromOmdb(data));
      onStatus('Готово: данные подставлены. Теперь поставь оценки и нажми “Добавить”.');
    } catch {
      if (version === generation) onStatus('Ошибка при загрузке деталей из OMDb.', true);
    }
  }
  function cancel() { generation++; search.cancel(); }
  return {
    select,
    cancel,
    search(query) { generation++; return search.search(query); },
    schedule(query) { generation++; search.schedule(query); },
  };
}
