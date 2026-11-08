const normalize = value => String(value ?? "").trim().toLowerCase();
    export function getTopGenres(movies, limit = 8){
      const GENRE_RU = {
        "action":"боевик","adventure":"приключения","animation":"мультфильм",
        "biography":"биография","comedy":"комедия","crime":"криминал",
        "documentary":"документальный","drama":"драма","family":"семейный",
        "fantasy":"фэнтези","history":"история","horror":"ужасы",
        "music":"музыка","musical":"мюзикл","mystery":"мистика",
        "romance":"романтика","sci-fi":"фантастика","science fiction":"фантастика",
        "sport":"спорт","thriller":"триллер","war":"война","western":"вестерн",
        "action & adventure":"боевик и приключения","sci-fi & fantasy":"нф и фэнтези",
        "talk":"ток-шоу","reality":"реалити","news":"новости",
        "kids":"детский","soap":"мелодрама"
      };
      const counted = new Map();
      for(const m of movies){
        const parts = [];
        const omdbGenre = m.omdb?.genre || "";
        if(omdbGenre) parts.push(...String(omdbGenre).split(",").map(x=>x.trim()).filter(Boolean));
        const tmdbGenres = m.tmdb?.genres || [];
        tmdbGenres.forEach(g => { if(g.name) parts.push(g.name.trim()); });

        for(const g of parts){
          const norm = normalize(g);
          if(!norm) continue;
          const ru = GENRE_RU[norm] || norm;
          counted.set(ru, (counted.get(ru) || 0) + 1);
        }
      }
      return [...counted.entries()]
        .sort((a,b) => b[1]-a[1])
        .slice(0, limit)
        .map(([k,c]) => ({ name: k, count: c }));
    }
