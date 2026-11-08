// Serializes writes so a slower response cannot overwrite a newer snapshot.
export function createSync({ request, getSnapshot, isAuthenticated, onStatus, onSaved, delay = 3000 }) {
  let timer = null;
  let running = null;
  let queued = false;
  async function flush() {
    clearTimeout(timer);
    timer = null;
    if (!isAuthenticated()) return;
    if (running) { queued = true; return running; }
    const snapshot = JSON.stringify(getSnapshot());
    onStatus('syncing');
    running = (async () => {
      try {
        await request('/api/data', { method: 'PUT', body: snapshot });
        onStatus('ok');
        onSaved?.(JSON.parse(snapshot));
      } catch (error) {
        onStatus('err');
        console.warn('syncToServer:', error.message);
      }
    })();
    try { await running; } finally {
      running = null;
      if (queued) { queued = false; return flush(); }
    }
  }
  function schedule() {
    if (!isAuthenticated()) return;
    clearTimeout(timer);
    timer = setTimeout(flush, delay);
  }
  function cancel() { clearTimeout(timer); timer = null; queued = false; }
  return { flush, schedule, cancel };
}
