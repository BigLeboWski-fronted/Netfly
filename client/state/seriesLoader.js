export function createSeriesLoader({ request, getCache, saveCache, onDetails }) {
  const pending = new Map();
  async function load(id, knownSeasons) {
    if(!id) return null;
    const cached = getCache()[id];
    if(cached?.seasons && !cached.incomplete) return cached;
    if(pending.has(id)) return pending.get(id);
    const task = (async () => {
      const entry = { ...cached, seasons:{ ...cached?.seasons }, incomplete:true };
      let details;
      try { details = await request({i:id,plot:'short'}); } catch {}
      if(details?.Response === 'True') {
        entry.totalSeasons = Number(details.totalSeasons) || knownSeasons || null;
        onDetails(id,details);
      }
      const count = Number(entry.totalSeasons || knownSeasons) || 0;
      let complete = count > 0;
      for(let season=1;season<=count;season++) {
        if(entry.seasons[season]?.length) continue;
        try {
          const data = await request({i:id,Season:season});
          if(data.Response !== 'True' || !Array.isArray(data.Episodes)) { complete=false; continue; }
          entry.seasons[season] = data.Episodes.map(episode => Object.fromEntries(['Episode','Title','Released','imdbRating','imdbID'].map(key=>[key,String(episode[key] || '')])));
        } catch { complete=false; }
      }
      entry.totalEpisodes = Object.values(entry.seasons).reduce((sum,episodes)=>sum+episodes.length,0) || null;
      entry.incomplete = !complete;
      saveCache(id,entry);
      return entry;
    })();
    pending.set(id,task);
    try { return await task; } finally { pending.delete(id); }
  }
  return {load};
}
