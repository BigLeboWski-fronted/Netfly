    function ymd(d){
      const dt = d instanceof Date ? d : new Date(d);
      const y = dt.getFullYear();
      const m = String(dt.getMonth()+1).padStart(2,"0");
      const dd = String(dt.getDate()).padStart(2,"0");
      return `${y}-${m}-${dd}`;
    }

    export function getNowWatchedCount(nowState, omdbEpCache, now = Date.now()){
      return Object.values(nowState.watched || {}).filter(Boolean).length;
    }

    export function getNowTotalCount(nowState, omdbEpCache, now = Date.now()){
      // Use cache if available
      if(!nowState.imdbID) return null;
      const entry = omdbEpCache[nowState.imdbID];
      if(entry && entry.totalEpisodes) return Number(entry.totalEpisodes) || null;
      return null;
    }

    export function computeNowProgress(nowState, omdbEpCache, now = Date.now()){
      const watched = getNowWatchedCount(nowState, omdbEpCache);
      const total = getNowTotalCount(nowState, omdbEpCache);
      const pct = total ? Math.round((watched/total)*100) : null;
      return { watched, total, pct };
    }

    export function getNextUnwatched(nowState, omdbEpCache, now = Date.now()){
      if(!nowState.imdbID) return null;
      const entry = omdbEpCache[nowState.imdbID];
      if(!entry || !entry.seasons) return null;
      const seasons = Object.keys(entry.seasons).map(n=>Number(n)).filter(n=>n>0).sort((a,b)=>a-b);
      for(const s of seasons){
        const eps = entry.seasons[String(s)] || [];
        for(const ep of eps){
          const key = `S${s}E${ep.Episode}`;
          if(!nowState.watched[key]) return { season: s, episode: Number(ep.Episode), title: ep.Title || "" };
        }
      }
      return null;
    }

    export function computeStreak(nowState, omdbEpCache, now = Date.now()){
      if(!nowState.streakOn) return 0;
      const days = (nowState.activityDays || []).slice().sort();
      if(!days.length) return 0;
      // count consecutive ending today
      const today = ymd(now);
      let streak = 0;
      let cur = today;
      const set = new Set(days);
      while(set.has(cur)){
        streak += 1;
        const dt = new Date(cur + "T00:00:00");
        dt.setDate(dt.getDate()-1);
        cur = ymd(dt);
      }
      return streak;
    }

    export function computeWeeksWatching(nowState, omdbEpCache, now = Date.now()){
      const activity = Array.isArray(nowState.activityDays) ? nowState.activityDays.filter(Boolean) : [];
      let startTs = null;
      if(activity.length){
        const first = activity.slice().sort()[0];
        startTs = new Date(first + "T00:00:00").getTime();
      }else if(Array.isArray(nowState.watchLog) && nowState.watchLog.length){
        const times = nowState.watchLog.map(it => Number(it.ts || 0)).filter(Boolean).sort((a,b)=>a-b);
        startTs = times[0] || null;

      }else if(Number.isFinite(Number(nowState.startedAt))){
        startTs = Number(nowState.startedAt);


      }
      if(!startTs) return null;
      const days = Math.max(1, Math.floor((now - startTs) / 86400000) + 1);
      return Math.max(1, Math.ceil(days / 7));
    }

    export function sumMinutesLast7Days(nowState, omdbEpCache, now = Date.now()){
      const from = now - 7*86400000;
      const log = Array.isArray(nowState.watchLog) ? nowState.watchLog : [];
      let eps = 0, min = 0;
      for(const it of log){
        const ts = Number(it.ts || 0);
        if(ts >= from){
          eps += Number(it.eps || 0);
          min += Number(it.minutes || 0);
        }
      }
      return { eps, minutes: min };
    }
