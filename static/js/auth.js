/* LazyOwnBT — helpers comunes de autenticación en el cliente.
   Mantiene la convención de usar sessionStorage (mismo nombre de
   clave que login.html) para que la pestaña caduque al cerrar.
*/

const AUTH = (() => {
  const KEY = "jwt_token";
  return {
    get() { return sessionStorage.getItem(KEY) || null; },
    set(t) { sessionStorage.setItem(KEY, t); },
    clear() { sessionStorage.removeItem(KEY); },
    requireOrRedirect(loginUrl = "/login") {
      if (!this.get()) { window.location.href = loginUrl; return false; }
      return true;
    },
    async fetch(url, options = {}) {
      const token = this.get();
      const headers = Object.assign(
        { "Content-Type": "application/json" },
        options.headers || {},
      );
      if (token) { headers["Authorization"] = `Bearer ${token}`; }
      const res = await fetch(url, Object.assign({}, options, { headers }));
      if (res.status === 401) {
        this.clear();
        window.location.href = "/login";
        throw new Error("unauthorized");
      }
      return res;
    },
  };
})();

if (typeof window !== "undefined") { window.AUTH = AUTH; }
