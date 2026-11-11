"use strict";
(() => {
  const q = new URLSearchParams(location.search);
  const next = q.get("next") || "/";
  document.getElementById("next").value = (next.startsWith("/") && !next.startsWith("//") ? next : "/") + location.hash;
  const msg = document.getElementById("login-msg");
  if (q.get("error")) { msg.textContent = "Incorrect username or password."; msg.hidden = false; }
  else if (q.get("expired")) { msg.textContent = "The access link has expired or has already been used. Sign in with your account."; msg.hidden = false; }
})();
