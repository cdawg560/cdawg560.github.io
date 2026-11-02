const COOKIE_NAME = "mendocino_access";
const SESSION_SECONDS = 60 * 60 * 24 * 7;

function base64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return base64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

async function makeToken(secret, expires) {
  const payload = String(expires);
  return `${payload}.${await hmac(secret, payload)}`;
}

async function validToken(token, secret) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const expires = Number(parts[0]);
  if (!Number.isFinite(expires) || expires < Math.floor(Date.now() / 1000)) return false;
  return (await hmac(secret, parts[0])) === parts[1];
}

function cookieValue(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const item of cookies.split(";")) {
    const [key, ...rest] = item.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}

function loginPage(message = "") {
  const escaped = message.replace(/[&<>"]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#6d237d">
<title>May in Mendocino</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body{
 min-height:100svh;display:flex;align-items:center;justify-content:center;
 padding:clamp(16px,4vw,40px);
 background:#46334e url("/assets/images/mendocino-background.png") center center/cover no-repeat fixed;
}
body:before{content:"";position:fixed;inset:0;background:linear-gradient(180deg,rgba(36,15,52,.10),rgba(36,15,52,.20));pointer-events:none}
.login-card{
 position:relative;width:min(100%,690px);padding:clamp(26px,4.5vw,48px);
 border:1px solid rgba(255,255,255,.78);border-radius:30px;
 background:rgba(255,245,250,.72);box-shadow:0 18px 55px rgba(35,12,45,.25);
 backdrop-filter:blur(15px);-webkit-backdrop-filter:blur(15px);text-align:center;
}
.coast-mark{width:min(68%,320px);height:auto;display:block;margin:0 auto 2px;color:#4b235e}
h1{font-family:"Brush Script MT","Segoe Script","Apple Chancery",cursive;font-weight:500;
 font-size:clamp(2.55rem,7vw,4.5rem);line-height:1.08;color:#55146d;margin:0 0 10px;letter-spacing:-.025em}
.subtitle{display:flex;align-items:center;gap:14px;justify-content:center;color:#24172a;
 font-size:clamp(1.05rem,3.1vw,1.6rem);margin:0 0 22px;white-space:nowrap}
.subtitle:before,.subtitle:after{content:"";height:2px;background:#5b2670;flex:1;max-width:70px}
.prompt{font-size:clamp(1rem,2.6vw,1.35rem);color:#18131b;margin:0 0 20px}
.error{color:#8a1739;font-size:.95rem;margin:-8px 0 14px}
.password-wrap{position:relative}
.password-wrap input{width:100%;height:64px;border:0;border-radius:40px;background:#fff;
 padding:0 58px 0 58px;font-size:1.15rem;color:#24212a;outline:2px solid transparent}
.password-wrap input:focus{outline-color:#8d4aa1}
.lock{position:absolute;left:24px;top:50%;transform:translateY(-50%);width:22px;height:22px;color:#38333b}
.toggle{position:absolute;right:15px;top:50%;transform:translateY(-50%);border:0;background:transparent;
 padding:10px;cursor:pointer;color:#29232e;display:flex}
.toggle svg{width:23px;height:23px}
.submit{margin-top:22px;width:100%;height:64px;border:0;border-radius:40px;background:#4c075d;
 color:white;font-size:1.25rem;font-weight:600;cursor:pointer;box-shadow:0 6px 16px rgba(66,8,77,.16)}
.submit:hover{background:#5c1470}.submit:focus-visible,.toggle:focus-visible{outline:3px solid #d6a7e2;outline-offset:3px}
.arrow{font-size:1.4em;vertical-align:-.06em;margin-left:8px}
@media(max-width:600px){
 body{padding:14px;background-attachment:scroll;background-position:center center}
 .login-card{padding:26px 20px;border-radius:24px;width:100%;background:rgba(255,245,250,.82)}
 .coast-mark{width:62%;max-width:230px}
 h1{font-size:clamp(2.15rem,10vw,3.25rem);overflow-wrap:anywhere}
 .subtitle{font-size:clamp(.92rem,4.2vw,1.2rem);gap:9px;margin-bottom:18px}
 .subtitle:before,.subtitle:after{max-width:36px}
 .prompt{font-size:1rem;line-height:1.4;margin-bottom:16px}
 .password-wrap input{height:58px;font-size:1rem;padding-left:50px;padding-right:50px}
 .lock{left:19px;width:20px;height:20px}
 .submit{height:58px;font-size:1.12rem;margin-top:16px}
}
@media(max-height:650px) and (max-width:600px){
 body{align-items:flex-start}
 .login-card{margin:auto 0}
}
</style>
</head>
<body>
<main class="login-card">
<svg class="coast-mark" viewBox="0 0 320 94" aria-hidden="true">
<g fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">
<path d="M18 76 Q75 62 128 72 T302 70"/>
<path d="M44 65l-13-20 13 5 10-20 10 20 12-5-14 20"/>
<path d="M88 69l-17-28 17 7 13-24 14 24 13-7-18 28"/>
<path d="M180 68V29h19v39M176 29h27l-4-8h-19zM184 40h11M184 50h11"/>
<path d="M167 68h46"/>
<path d="M232 23q10-11 20 0q-10 10-20 0zM263 36q8-9 16 0q-8 8-16 0z"/>
</g>
</svg>
<h1>May in Mendocino</h1>
<div class="subtitle">Is a Private Website</div>
<p class="prompt">Please enter the password to continue</p>
${escaped ? `<p class="error" role="alert">${escaped}</p>` : ""}
<form method="POST" action="/_login">
<div class="password-wrap">
<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15" r="1"/><path d="M12 16v2"/></svg>
<input id="password" name="password" type="password" placeholder="Enter password" autocomplete="current-password" required autofocus>
<button class="toggle" type="button" id="toggle" aria-label="Show password" title="Show password">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
</button>
</div>
<button class="submit" type="submit">Enter <span class="arrow">→</span></button>
</form>
</main>
<script>
const input=document.getElementById("password"),toggle=document.getElementById("toggle");
toggle.addEventListener("click",()=>{const show=input.type==="password";input.type=show?"text":"password";toggle.setAttribute("aria-label",show?"Hide password":"Show password");toggle.title=show?"Hide password":"Show password";});
</script>
</body></html>`;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const password = env.SITE_PASSWORD;
  const secret = env.SESSION_SECRET;

  // Let the login endpoint and its visual assets load without a session.
  if (url.pathname === "/favicon.svg" ||
      url.pathname === "/assets/images/mendocino-background.png") {
    return context.next();
  }

  if (!password || !secret) {
    return new Response("Login is not configured yet. Please try again later.", {
      status: 503, headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  }

  if (url.pathname === "/_login" && request.method === "POST") {
    const form = await request.formData();
    const submitted = String(form.get("password") || "");
    if (submitted !== password) {
      return new Response(loginPage("Incorrect password. Please try again."), {
        status: 401, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
      });
    }
    const expires = Math.floor(Date.now()/1000) + SESSION_SECONDS;
    const token = await makeToken(secret, expires);
    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (url.pathname === "/_login") {
    return new Response(loginPage(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
  }

  const token = cookieValue(request, COOKIE_NAME);
  if (await validToken(token, secret)) return context.next();

  return new Response(loginPage(), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
  });
}
