// gridscan-ui / index.js
// Entry-point redirect: send the user to the dashboard if already
// authenticated, otherwise to the login page.

(async () => {
  try {
    const session = await api.session();
    window.location.href = session && session.authenticated ? "dashboard.html" : "login.html";
  } catch (e) {
    window.location.href = "login.html";
  }
})();
