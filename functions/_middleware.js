const COOKIE_NAME = "site_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7; // 7 days

export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);

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
<title>May in Mendocino</title>
<style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f3f4f6;color:#1f2937;font:16px system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  .card{width:min(100%,380px);background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:32px;box-shadow:0 12px 36px rgba(0,0,0,.08)}
  h1{margin:0 0 8px;text-align:center;font-size:25px}p{margin:0 0 24px;text-align:center;color:#6b7280}
  label{display:block;margin-bottom:8px;font-weight:600;font-size:14px}input{width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:10px;font:inherit;margin-bottom:16px}
  input:focus{outline:3px solid #bfdbfe;border-color:#2563eb}button{width:100%;border:0;border-radius:10px;padding:13px;background:#2563eb;color:white;font:inherit;font-weight:600;cursor:pointer}button:hover{background:#1d4ed8}
  .message{margin:0 0 16px;color:#b91c1c;text-align:center;font-size:14px}
</style>
</head>
<body>
<main class="card">
  <h1>May in Mendocino</h1>
  <p>Enter the password to continue.</p>
  ${safeMessage ? `<div class="message" role="alert">${safeMessage}</div>` : ""}
  <form method="post" action="/login">
    <input type="hidden" name="return" value="${safeReturn}">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">Unlock</button>
  </form>
</main>
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
