
const corsHeaders = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64url(await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(value)
  ));
}

async function createSession(env) {
  const payload = base64url(new TextEncoder().encode(
    JSON.stringify({ user: env.ADMIN_USERNAME, exp: Date.now() + 28800000 })
  ));
  return payload + "." + await sign(payload, env.SESSION_SECRET);
}

async function checkSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/lala_admin=([^;]+)/);
  if (!match || !env.SESSION_SECRET) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const expected = await sign(parts[0], env.SESSION_SECRET);
  if (expected !== parts[1]) return false;

  try {
    const payload = JSON.parse(
      atob(parts[0].replace(/-/g, "+").replace(/_/g, "/"))
    );
    return payload.user === env.ADMIN_USERNAME &&
      payload.exp > Date.now();
  } catch {
    return false;
  }
}

async function setupDB(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price REAL NOT NULL,
      category TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      stock INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path.startsWith("/api/")) {
      if (!env.DB) return json({ error: "Database binding DB is missing." }, 500);

      try {
        await setupDB(env);

        if (path === "/api/login" && method === "POST") {
          if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
            return json({ error: "Admin secrets are not configured." }, 500);
          }

          const body = await request.json();
          if (
            body.username !== env.ADMIN_USERNAME ||
            body.password !== env.ADMIN_PASSWORD
          ) {
            return json({ error: "Incorrect username or password." }, 401);
          }

          const token = await createSession(env);
          return new Response(JSON.stringify({ success: true }), {
            headers: {
              ...corsHeaders,
              "Set-Cookie": `lala_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
            }
          });
        }

        if (path === "/api/logout" && method === "POST") {
          return new Response(JSON.stringify({ success: true }), {
            headers: {
              ...corsHeaders,
              "Set-Cookie": "lala_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
            }
          });
        }

        if (path === "/api/me" && method === "GET") {
          return json({ authenticated: await checkSession(request, env) });
        }

        if (path === "/api/products" && method === "GET") {
          const result = await env.DB.prepare(
            "SELECT * FROM products ORDER BY created_at DESC"
          ).all();
          return json({ products: result.results || [] });
        }

        const authenticated = await checkSession(request, env);
        if (!authenticated) {
          return json({ error: "Private admin access required." }, 401);
        }

        if (path === "/api/products" && method === "POST") {
          const body = await request.json();
          if (!body.name || !body.category || !Number.isFinite(Number(body.price))) {
            return json({ error: "Name, category and valid price are required." }, 400);
          }

          const id = crypto.randomUUID();
          await env.DB.prepare(`
            INSERT INTO products
            (id, name, description, price, category, image_url, stock)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).bind(
            id,
            String(body.name),
            String(body.description || ""),
            Number(body.price),
            String(body.category),
            String(body.image_url || ""),
            Math.max(0, Number(body.stock) || 0)
          ).run();

          return json({ success: true, id }, 201);
        }

        const productMatch = path.match(/^\/api\/products\/([a-zA-Z0-9-]+)$/);

        if (productMatch && method === "PUT") {
          const body = await request.json();
          await env.DB.prepare(`
            UPDATE products SET name=?, description=?, price=?,
            category=?, image_url=?, stock=? WHERE id=?
          `).bind(
            String(body.name),
            String(body.description || ""),
            Number(body.price),
            String(body.category),
            String(body.image_url || ""),
            Math.max(0, Number(body.stock) || 0),
            productMatch[1]
          ).run();

          return json({ success: true });
        }

        if (productMatch && method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM products WHERE id=?"
          ).bind(productMatch[1]).run();

          return json({ success: true });
        }

        return json({ error: "API route not found." }, 404);

      } catch (error) {
        return json({ error: "Server error. Check Worker logs." }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
