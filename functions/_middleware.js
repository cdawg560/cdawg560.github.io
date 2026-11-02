const COOKIE_NAME = "site_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);

  // Public visual assets used by the login page must remain reachable.
  if (url.pathname === "/assets/images/tulip-background.png" ||
      url.pathname === "/favicon.svg" || url.pathname === "/favicon.png" || url.pathname === "/favicon.ico") {
    return next();
  }

  // Login endpoint is the only unauthenticated route.
  if (url.pathname === "/login" && request.method === "GET") {
    return loginPage(url);
  }

  if (url.pathname === "/login" && request.method === "POST") {
    return handleLogin(request, env, url);
  }

  if (url.pathname === "/logout") {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/login",
        "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
        "Cache-Control": "no-store",
      },
    });
  }

  const cookie = getCookie(request, COOKIE_NAME);
  if (cookie && await isValidSession(cookie, env)) {
    return next();
  }

  // Keep the redirect destination local to this host.
  const destination = url.pathname + url.search;
  return new Response(null, {
    status: 302,
    headers: {
      Location: `/login?return=${encodeURIComponent(destination)}`,
      "Cache-Control": "no-store",
    },
  });
}

async function handleLogin(request, env, url) {
  if (!env.SITE_PASSWORD || !env.SESSION_SECRET) {
    return new Response(loginHtml("Login is not configured yet. Please try again later."), {
      status: 500,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  const form = await request.formData();
  const password = String(form.get("password") || "");
  const expected = String(env.SITE_PASSWORD);

  if (!constantTimeEqual(password, expected)) {
    return new Response(loginHtml("Incorrect password. Please try again."), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  const token = await createSession(env.SESSION_SECRET);
  const returnTo = safeReturnPath(form.get("return"));
  return new Response(null, {
    status: 302,
    headers: {
      Location: returnTo,
      "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`,
      "Cache-Control": "no-store",
    },
  });
}

function loginPage(url) {
  // Preserve a safe local destination after successful login.
  const returnTo = safeReturnPath(url.searchParams.get("return"));
  return new Response(loginHtml("", returnTo), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function loginHtml(message = "", returnTo = "/") {
  const safeReturn = escapeHtml(safeReturnPath(returnTo));
  const safeMessage = escapeHtml(message);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#66256f">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="/favicon.ico">
<title>Private Website</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;min-height:100svh;display:grid;place-items:center;padding:22px;
    background:#5a345f url('/assets/images/tulip-background.png') center center/cover fixed no-repeat;
    color:#24172a;font:16px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  body:before{content:"";position:fixed;inset:0;background:rgba(38,15,48,.12);pointer-events:none}
  .card{position:relative;width:min(100%,690px);padding:clamp(28px,5vw,54px);border:2px solid rgba(255,255,255,.65);
    border-radius:30px;background:rgba(255,245,250,.58);box-shadow:0 18px 55px rgba(35,10,42,.2);
    backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
  h1{margin:0 0 14px;text-align:center;color:#69216f;font-family:"Brush Script MT","Segoe Script",cursive;
    font-size:clamp(42px,7vw,76px);font-weight:400;line-height:1.15;letter-spacing:-1px}
  p{margin:0 0 30px;text-align:center;color:#211a22;font-size:clamp(16px,2.4vw,22px)}
  .message{margin:0 0 18px;color:#9e1749;text-align:center;font-size:14px;font-weight:600}
  .field{position:relative;margin-bottom:22px}
  input{display:block;width:100%;height:74px;padding:0 62px 0 26px;border:1px solid rgba(80,50,80,.18);border-radius:40px;
    background:rgba(255,255,255,.96);font:inherit;font-size:22px;color:#2a2030;box-shadow:0 3px 10px rgba(45,15,50,.06)}
  input:focus{outline:3px solid rgba(125,47,135,.32);border-color:#7d2f87}
  input::placeholder{color:#777}
  .toggle{position:absolute;right:12px;top:50%;transform:translateY(-50%);width:44px;height:44px;border:0;background:transparent;
    color:#403746;cursor:pointer;border-radius:50%;display:grid;place-items:center}
  .toggle:hover{background:#f3e8f5}
  .toggle svg{width:24px;height:24px}
  button.submit{width:100%;min-height:68px;border:0;border-radius:40px;padding:14px 22px;background:linear-gradient(100deg,#68266f,#54185e);
    color:#fff;font:inherit;font-size:22px;font-weight:600;cursor:pointer;box-shadow:0 8px 18px rgba(71,20,80,.18);transition:transform .15s,filter .15s}
  button.submit:hover{filter:brightness(1.08);transform:translateY(-1px)}
  button.submit:focus-visible,.toggle:focus-visible{outline:3px solid #fff;outline-offset:3px}
  @media(max-width:520px){body{padding:16px;background-attachment:scroll}.card{padding:30px 22px;border-radius:24px}input{height:62px;font-size:18px;padding-left:20px}button.submit{min-height:60px;font-size:19px}p{margin-bottom:24px}}
  @media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<main class="card">
  <h1>Private Website</h1>
  <p>Enter the password to continue</p>
  ${safeMessage ? `<div class="message" role="alert">${safeMessage}</div>` : ""}
  <form method="post" action="/login">
    <input type="hidden" name="return" value="${safeReturn}">
    <div class="field">
      <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Enter password" aria-label="Password" required autofocus>
      <button class="toggle" type="button" id="togglePassword" aria-label="Show password" title="Show password">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
    </div>
    <button class="submit" type="submit">Unlock&nbsp; →</button>
  </form>
</main>
<script>
  const field=document.getElementById('password');
  const toggle=document.getElementById('togglePassword');
  toggle.addEventListener('click',()=>{const showing=field.type==='password';field.type=showing?'text':'password';toggle.setAttribute('aria-label',showing?'Hide password':'Show password');toggle.title=showing?'Hide password':'Show password';field.focus();});
</script>
</body>
</html>`;
}

async function createSession(secret) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = `${issuedAt}`;
  const signature = await hmac(payload, secret);
  return `${payload}.${signature}`;
}

async function isValidSession(token, env) {
  if (!env.SESSION_SECRET) return false;
  const parts = token.split(".");
  if (parts.length !== 2 || !/^\d+$/.test(parts[0])) return false;
  const issuedAt = Number(parts[0]);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(issuedAt) || issuedAt > now || now - issuedAt > SESSION_SECONDS) return false;
  const expected = await hmac(parts[0], env.SESSION_SECRET);
  return constantTimeEqual(parts[1], expected);
}

async function hmac(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return toBase64Url(new Uint8Array(signature));
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const item of cookies.split(";")) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return value.join("=");
  }
  return "";
}

function constantTimeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  const length = Math.max(x.length, y.length);
  for (let i = 0; i < length; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function safeReturnPath(value) {
  const path = String(value || "/");
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) return "/";
  return path;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}
