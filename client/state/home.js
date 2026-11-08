const normalize = value => String(value ?? "").trim().toLowerCase();
const computeScores = scores => ({final:["overall","engage","emotions"].reduce((sum,key)=>sum+Math.max(0,Math.min(10,Number(scores?.[key])||0)),0)/3});
const formatFinalScore = value => Number.isFinite(value) ? Math.min(10,value).toFixed(1) : "—";
export function recentMovies(movies){
  return movies.filter(movie=>(movie.status || "watched")==="watched").slice().sort((a,b)=>(b.createdAt || 0)-(a.createdAt || 0)).slice(0,3).map(movie=>({id:movie.id,name:movie.name || "Без названия",posterUrl:movie.omdb?.posterUrl || null,score:formatFinalScore(computeScores(movie.scores).final)}));
}
    function getMovieGenres(movie){
      return String(movie?.omdb?.genre || "")
        .split(",")
        .map(x => normalize(x))
        .filter(Boolean);
    }

    export function getSmartRecommendation(movies, profile){
      const rated = movies.filter(m => (m.status || "watched") === "watched");
      const candidates = movies.filter(m => (m.status || "watched") === "wish");
      if(!candidates.length) return null;

      const topRated = rated
        .slice()
        .sort((a,b) => computeScores(b.scores).final - computeScores(a.scores).final)
        .slice(0, 8);
      const genreWeights = {};
      topRated.forEach(movie => getMovieGenres(movie).forEach(g => {
        genreWeights[g] = (genreWeights[g] || 0) + 1;
      }));

      const favDirector = normalize(profile.favDirectorName || "");
      const favActor = normalize(profile.favActorName || "");
      let best = null;

      candidates.forEach(movie => {
        const genres = getMovieGenres(movie);
        const actors = (Array.isArray(movie.omdb?.actors) ? movie.omdb.actors : []).map(normalize);
        const director = normalize(movie.director || movie.omdb?.director || "");
        let score = 0;
        const reasons = [];

        if(favDirector && director.includes(favDirector)){
          score += 8; reasons.push("любимый режиссёр");
        }
        if(favActor && actors.some(actor => actor.includes(favActor))){
          score += 8; reasons.push("любимый актёр");
        }

        const matchingGenres = genres.filter(g => genreWeights[g]);
        score += matchingGenres.reduce((sum, g) => sum + genreWeights[g] * 2, 0);
        if(matchingGenres.length) reasons.push("любимые жанры");

        const similarTo = topRated.find(ratedMovie => {
          const overlap = genres.filter(g => getMovieGenres(ratedMovie).includes(g));
          return overlap.length >= 2;
        });
        if(similarTo){
          score += 4;
          reasons.push(`похож на «${similarTo.name}»`);
        }

        // Keep queue order as a stable tie-breaker.
        score += Math.max(0, 1 - Number(movie.queueOrder || 1) / 100);
        if(!best || score > best.score) best = { movie, score, reasons };
      });

      if(!best) return null;
      return {
        ...best,
        reason: best.reasons.length ? best.reasons.slice(0, 2).join(" • ") : "из твоей очереди"
      };
    }

    export function dashboardData(movies, profile, nowState){

      const rated = movies
        .filter(m => (m.status || "watched") === "watched")
        .sort((a,b) => (b.createdAt ?? 0) - (a.createdAt ?? 0));
      const last = rated[0] || null;
      const recommendation = getSmartRecommendation(movies, profile);
      const nowTitle = String(nowState.title || "").trim();
      const monthStart = new Date();
      monthStart.setDate(1); monthStart.setHours(0,0,0,0);
      const monthRated = rated.filter(m => Number(m.createdAt || 0) >= monthStart.getTime());
      const monthScores = monthRated.map(m => computeScores(m.scores).final).filter(Number.isFinite);
      const monthAvg = monthScores.length
        ? formatFinalScore(monthScores.reduce((a,b) => a + b, 0) / monthScores.length)
        : "—";

      const card = (icon, label, value, meta, action) => ({ icon, label, value, meta, action });
      return ({
        cards: [
          card("▶", "Смотрю сейчас", nowTitle || "Ничего не выбрано", nowTitle ? "Продолжить просмотр" : "Открыть раздел", "now"),
          card("◷", "Последний просмотренный", last?.name || "Пока пусто", last ? `Оценка: ${formatFinalScore(computeScores(last.scores).final)}` : "Добавь первый фильм", last ? "rated" : "evaluate"),
          card("✦", "Рекомендация", recommendation?.movie.name || "Добавь фильм в очередь", recommendation?.reason || "Здесь появятся идеи", recommendation ? "wish" : "evaluate"),
          card("▦", "Статистика за месяц", `${monthRated.length} фильм${monthRated.length === 1 ? "" : monthRated.length < 5 ? "а" : "ов"}`, `Средняя оценка: ${monthAvg}`)
        ],
      });
    }
