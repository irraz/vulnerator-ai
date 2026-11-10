"use strict";
(() => {
  const q = new URLSearchParams(location.search);
  const next = q.get("next") || "/";
  document.getElementById("next").value = (next.startsWith("/") && !next.startsWith("//") ? next : "/") + location.hash;
  const msg = document.getElementById("login-msg");
  if (q.get("error")) { msg.textContent = "Usuario o contraseña incorrectos."; msg.hidden = false; }
  else if (q.get("expired")) { msg.textContent = "El enlace de acceso ha caducado o ya se usó. Entra con tu cuenta."; msg.hidden = false; }
})();
