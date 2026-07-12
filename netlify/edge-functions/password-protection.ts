const COOKIE_NAME = "senf_preview_session";
const SESSION_DURATION_SECONDS = 60 * 60 * 24;

function htmlPage(message = "", status = 200): Response {
  const error = message
    ? `<p class="message" role="alert">${escapeHtml(message)}</p>`
    : "";

  return new Response(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Aperçu privé — SENF</title>
  <style>
    :root { color-scheme: light; font-family: system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: #f2eee3; color: #1e241f; }
    main { width: min(100%, 430px); padding: 38px; background: #fffdf7; border: 1px solid #c9c0ae; box-shadow: 0 16px 45px rgb(52 44 35 / 10%); }
    h1 { margin: 0 0 12px; color: #183f2f; font-family: Georgia, serif; font-size: 32px; }
    p { line-height: 1.55; }
    label { display: block; margin: 25px 0 8px; font-weight: 700; }
    input { width: 100%; padding: 12px; border: 1px solid #76513a; font: inherit; }
    button { width: 100%; margin-top: 15px; padding: 13px; border: 0; background: #183f2f; color: white; font: 700 16px system-ui, sans-serif; cursor: pointer; }
    .message { padding: 10px 12px; background: #f7e3df; color: #7b241c; }
    small { display: block; margin-top: 20px; color: #626860; line-height: 1.45; }
  </style>
</head>
<body>
  <main>
    <h1>Aperçu privé</h1>
    <p>Ce site est en cours de préparation. Saisissez le mot de passe communiqué par la SENF.</p>
    ${error}
    <form method="post">
      <label for="password">Mot de passe</label>
      <input id="password" name="password" type="password" required autofocus autocomplete="current-password">
      <button type="submit">Consulter le site</button>
    </form>
    <small>L’accès restera ouvert pendant 24 heures sur cet appareil.</small>
  </main>
</body>
</html>`, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow, noarchive",
    },
  });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  })[character] ?? character);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left: string, right: string): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index++) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
}

async function sign(payload: string, password: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return bytesToHex(new Uint8Array(signature));
}

async function validSession(request: Request, password: string): Promise<boolean> {
  const cookie = request.headers.get("cookie") ?? "";
  const rawValue = cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE_NAME}=`))?.split("=")[1];
  if (!rawValue) return false;

  const [expiresAt, suppliedSignature] = rawValue.split(".");
  if (!expiresAt || !suppliedSignature || Number(expiresAt) <= Math.floor(Date.now() / 1000)) return false;

  const expectedSignature = await sign(expiresAt, password);
  return timingSafeEqual(suppliedSignature, expectedSignature);
}

export default async (request: Request, context: { next: () => Promise<Response> }) => {
  const password = Netlify.env.get("PROTECTED_PAGE_PASSWORD");
  if (!password) {
    return htmlPage("La protection n’est pas encore configurée par le propriétaire du site.", 503);
  }

  const url = new URL(request.url);
  if (url.searchParams.get("logout") === "1") {
    return new Response(null, {
      status: 303,
      headers: {
        location: `${url.origin}/`,
        "set-cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
      },
    });
  }

  if (await validSession(request, password)) return context.next();

  if (request.method === "POST") {
    const form = await request.formData();
    const suppliedPassword = String(form.get("password") ?? "");
    const [suppliedHash, expectedHash] = await Promise.all([sha256(suppliedPassword), sha256(password)]);

    if (timingSafeEqual(suppliedHash, expectedHash)) {
      const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
      const signature = await sign(String(expiresAt), password);
      return new Response(null, {
        status: 303,
        headers: {
          location: request.url,
          "set-cookie": `${COOKIE_NAME}=${expiresAt}.${signature}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DURATION_SECONDS}`,
        },
      });
    }

    return htmlPage("Mot de passe incorrect.", 401);
  }

  return htmlPage();
};

