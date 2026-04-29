(function () {
  function createAuthSync(ctx) {
    const API = "";
    let syncTimer = null;
    let currentUser = null;
    let authMode = "login";

    const authSubmit = document.getElementById("authSubmit");
    const authError = document.getElementById("authError");

    function setSyncDot(state) {
      const d = document.getElementById("syncDot");
      if (!d) return;
      d.className = "syncDot " + state;
    }

    async function apiFetch(path, opts) {
      const res = await fetch(API + path, {
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        ...(opts || {}),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }

    async function loadFromServer() {
      try {
        const data = await apiFetch("/api/data");
        if (Array.isArray(data.movies) && data.movies.length) {
          ctx.setMovies(data.movies);
          ctx.saveMovies();
        }
        if (data.profile && Object.keys(data.profile).length) {
          const local = ctx.loadProfile();
          const merged = { ...local, ...data.profile };
          if (!merged.avatar && local.avatar) merged.avatar = local.avatar;
          ctx.setProfile(merged);
          ctx.saveProfile(merged);
        }
        if (data.now_state && Object.keys(data.now_state).length) {
          const nextNowState = ctx.loadNowState();
          Object.assign(nextNowState, data.now_state);
          ctx.setNowState(nextNowState);
          ctx.saveNowState();
        }
        if (data.omdb_ep_cache && Object.keys(data.omdb_ep_cache).length) {
          const mergedCache = { ...ctx.getOmdbEpCache(), ...data.omdb_ep_cache };
          ctx.setOmdbEpCache(mergedCache);
          ctx.saveEpCache();
        }
      } catch (e) {
        console.warn("loadFromServer:", e.message);
      }
    }

    async function syncToServer() {
      if (!currentUser) return;
      setSyncDot("syncing");
      try {
        await apiFetch("/api/data", {
          method: "PUT",
          body: JSON.stringify({
            movies: ctx.getMovies(),
            profile: ctx.getProfile(),
            now_state: ctx.getNowState(),
            omdb_ep_cache: ctx.getOmdbEpCache(),
          }),
        });
        setSyncDot("ok");
      } catch (e) {
        setSyncDot("err");
        console.warn("syncToServer:", e.message);
      }
    }

    function scheduleSync() {
      if (!currentUser) return;
      clearTimeout(syncTimer);
      syncTimer = setTimeout(syncToServer, 3000);
    }

    function showApp(username) {
      currentUser = username;
      document.getElementById("authScreen").classList.add("hidden");
      const badge = document.getElementById("userBadge");
      badge.style.display = "flex";
      document.getElementById("userBadgeName").textContent = username;
    }

    function showAuthScreen() {
      currentUser = null;
      document.getElementById("authScreen").classList.remove("hidden");
      document.getElementById("userBadge").style.display = "none";
    }

    function authSetError(msg) {
      authError.textContent = msg || "";
    }

    function authSetLoading(on) {
      authSubmit.disabled = on;
    }

    function showAuthStep(step) {
      document.getElementById("authStepLogin").style.display = step === "login" ? "" : "none";
      document.getElementById("authStepRegister").style.display = step === "register" ? "" : "none";
      document.getElementById("authStepCode").style.display = step === "code" ? "" : "none";
      document.getElementById("authStepForgot").style.display = step === "forgot" ? "" : "none";
      document.getElementById("authStepReset").style.display = step === "resetCode" ? "" : "none";
      document.getElementById("forgotPasswordLink").style.display = step === "login" ? "" : "none";
    }

    function initAuthUi() {
      document.getElementById("tabLogin").addEventListener("click", function () {
        authMode = "login";
        document.getElementById("tabLogin").classList.add("active");
        document.getElementById("tabRegister").classList.remove("active");
        authSubmit.textContent = "Войти";
        showAuthStep("login");
        authSetError("");
      });

      document.getElementById("tabRegister").addEventListener("click", function () {
        authMode = "register";
        document.getElementById("tabRegister").classList.add("active");
        document.getElementById("tabLogin").classList.remove("active");
        authSubmit.textContent = "Получить код";
        showAuthStep("register");
        authSetError("");
      });

      authSubmit.addEventListener("click", async function () {
        authSetError("");
        authSetLoading(true);
        const origText = authSubmit.textContent;
        authSubmit.textContent = "...";

        try {
          if (authMode === "login") {
            const email = document.getElementById("authEmail").value.trim();
            const password = document.getElementById("authPassword").value;
            const data = await apiFetch("/api/login", {
              method: "POST",
              body: JSON.stringify({ email, password }),
            });
            showApp(data.username);
            await loadFromServer();
            ctx.applyAvatar(ctx.getProfile().avatar || null);
            ctx.renderEverything();
          } else if (authMode === "register") {
            const email = document.getElementById("authRegEmail").value.trim();
            const username = document.getElementById("authRegUsername").value.trim();
            const password = document.getElementById("authRegPassword").value;
            await apiFetch("/api/send-code", {
              method: "POST",
              body: JSON.stringify({ email, username, password }),
            });
            authMode = "code";
            document.getElementById("authCodeEmailHint").textContent = email;
            showAuthStep("code");
            authSubmit.textContent = "Подтвердить";
            document.getElementById("authCode").focus();
          } else if (authMode === "code") {
            const email = document.getElementById("authRegEmail").value.trim();
            const username = document.getElementById("authRegUsername").value.trim();
            const password = document.getElementById("authRegPassword").value;
            const code = document.getElementById("authCode").value.trim();
            const data = await apiFetch("/api/verify-code", {
              method: "POST",
              body: JSON.stringify({ email, username, password, code }),
            });
            showApp(data.username);
            await loadFromServer();
            ctx.applyAvatar(ctx.getProfile().avatar || null);
            ctx.renderEverything();
          } else if (authMode === "forgot") {
            const email = document.getElementById("authForgotEmail").value.trim();
            await apiFetch("/api/forgot-password", {
              method: "POST",
              body: JSON.stringify({ email }),
            });
            authMode = "resetCode";
            document.getElementById("authResetEmailHint").textContent = email;
            showAuthStep("resetCode");
            authSubmit.textContent = "Сменить пароль";
            document.getElementById("authResetCode").focus();
          } else if (authMode === "resetCode") {
            const email = document.getElementById("authForgotEmail").value.trim();
            const code = document.getElementById("authResetCode").value.trim();
            const password = document.getElementById("authNewPassword").value;
            await apiFetch("/api/reset-password", {
              method: "POST",
              body: JSON.stringify({ email, code, password }),
            });
            authMode = "login";
            showAuthStep("login");
            authSubmit.textContent = "Войти";
            authSetError("");
            document.getElementById("authEmail").value = email;
          }
        } catch (e) {
          authSetError(e.message);
          authSubmit.textContent = origText;
        } finally {
          authSetLoading(false);
          if (authMode !== "code") authSubmit.textContent = origText;
        }
      });

      [
        "authEmail",
        "authPassword",
        "authRegEmail",
        "authRegUsername",
        "authRegPassword",
        "authCode",
        "authForgotEmail",
        "authResetCode",
        "authNewPassword",
      ].forEach(function (id) {
        const el = document.getElementById(id);
        if (el) {
          el.addEventListener("keydown", function (e) {
            if (e.key === "Enter") authSubmit.click();
          });
        }
      });

      document.getElementById("forgotPasswordLink").addEventListener("click", function () {
        authMode = "forgot";
        showAuthStep("forgot");
        authSubmit.textContent = "Отправить код";
        authSetError("");
        document.getElementById("authForgotEmail").focus();
      });

      document.getElementById("logoutBtn").addEventListener("click", async function () {
        await apiFetch("/api/logout", { method: "POST" }).catch(function () {});
        showAuthScreen();
      });
    }

    async function checkSession() {
      try {
        const data = await apiFetch("/api/me");
        showApp(data.username);
        await loadFromServer();
        ctx.applyAvatar(ctx.getProfile().avatar || null);
      } catch (_e) {
        showAuthScreen();
      }
    }

    initAuthUi();

    return {
      apiFetch,
      checkSession,
      scheduleSync,
      getCurrentUser: function () {
        return currentUser;
      },
    };
  }

  window.NetflyAuthSync = { createAuthSync: createAuthSync };
})();
