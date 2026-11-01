
const corsHeaders = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store"
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, ...extraHeaders }
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
    "HMAC",
    key,
    new TextEncoder().encode(value)
  ));
}

async function createSession(env) {
  const payload = base64url(new TextEncoder().encode(
    JSON.stringify({
      user: env.ADMIN_USERNAME,
      exp: Date.now() + 28800000
    })
  ));

  return payload + "." + await sign(payload, env.SESSION_SECRET);
}

async function checkSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/lala_admin=([^;]+)/);

  if (!match || !env.SESSION_SECRET || !env.ADMIN_USERNAME) {
    return false;
  }

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const expected = await sign(parts[0], env.SESSION_SECRET);

  if (expected !== parts[1]) return false;

  try {
    let encoded = parts[0]
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    encoded += "=".repeat((4 - encoded.length % 4) % 4);

    const payload = JSON.parse(atob(encoded));

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
      image_urls TEXT DEFAULT '[]',
      stock INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Add the gallery column to existing databases without deleting products.
  const columns = await env.DB.prepare(
    "PRAGMA table_info(products)"
  ).all();

  const hasGallery = (columns.results || []).some(
    column => column.name === "image_urls"
  );

  if (!hasGallery) {
    await env.DB.prepare(
      "ALTER TABLE products ADD COLUMN image_urls TEXT DEFAULT '[]'"
    ).run();
  }
}

function cleanImages(body) {
  let images = body.image_urls;

  if (typeof images === "string") {
    try {
      images = JSON.parse(images);
    } catch {
      images = [];
    }
  }

  if (!Array.isArray(images)) images = [];

  images = images
    .filter(url => typeof url === "string" && /^https:\/\/res\.cloudinary\.com\//i.test(url))
    .slice(0, 10);

  if (!images.length && body.image_url) {
    const legacy = String(body.image_url);

    if (/^https:\/\/res\.cloudinary\.com\//i.test(legacy)) {
      images.push(legacy);
    }
  }

  return images;
}

function formatProduct(product) {
  let images = [];

  try {
    images = JSON.parse(product.image_urls || "[]");
  } catch {
    images = [];
  }

  if (!Array.isArray(images)) images = [];

  if (!images.length && product.image_url) {
    images = [product.image_url];
  }

  return {
    ...product,
    image_urls: images,
    image_url: images[0] || product.image_url || ""
  };
}

function validProduct(body) {
  return body &&
    String(body.name || "").trim() &&
    String(body.category || "").trim() &&
    Number.isFinite(Number(body.price)) &&
    Number(body.price) >= 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (!env.DB) {
      return json({ error: "Database binding DB is missing." }, 500);
    }

    try {
      await setupDB(env);

      // LOGIN
      if (path === "/api/login" && method === "POST") {
        if (
          !env.ADMIN_USERNAME ||
          !env.ADMIN_PASSWORD ||
          !env.SESSION_SECRET
        ) {
          return json({
            error: "Admin secrets are not configured."
          }, 500);
        }

        const body = await request.json();

        if (
          body.username !== env.ADMIN_USERNAME ||
          body.password !== env.ADMIN_PASSWORD
        ) {
          return json({
            error: "Incorrect username or password."
          }, 401);
        }

        const token = await createSession(env);

        return json(
          { success: true },
          200,
          {
            "Set-Cookie":
              `lala_admin=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
          }
        );
      }

      // LOGOUT
      if (path === "/api/logout" && method === "POST") {
        return json(
          { success: true },
          200,
          {
            "Set-Cookie":
              "lala_admin=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
          }
        );
      }

      // CHECK LOGIN
      if (path === "/api/me" && method === "GET") {
        return json({
          authenticated: await checkSession(request, env)
        });
      }

      // PUBLIC PRODUCT LIST
      if (path === "/api/products" && method === "GET") {
        const result = await env.DB.prepare(
          "SELECT * FROM products ORDER BY created_at DESC"
        ).all();

        return json({
          products: (result.results || []).map(formatProduct)
        });
      }

      // ALL REMAINING ROUTES REQUIRE ADMIN LOGIN
      const authenticated = await checkSession(request, env);

      if (!authenticated) {
        return json({
          error: "Private admin access required."
        }, 401);
      }

      // CLOUDINARY SIGNATURE
      if (
        path === "/api/cloudinary-signature" &&
        method === "POST"
      ) {
        if (
          !env.CLOUDINARY_CLOUD_NAME ||
          !env.CLOUDINARY_API_KEY ||
          !env.CLOUDINARY_API_SECRET
        ) {
          return json({
            error: "Cloudinary settings are missing."
          }, 500);
        }

        const timestamp = Math.floor(Date.now() / 1000);

        const toSign =
          "timestamp=" +
          timestamp +
          env.CLOUDINARY_API_SECRET;

        const digest = await crypto.subtle.digest(
          "SHA-1",
          new TextEncoder().encode(toSign)
        );

        const signature = Array.from(new Uint8Array(digest))
          .map(byte => byte.toString(16).padStart(2, "0"))
          .join("");

        return json({
          timestamp,
          signature,
          api_key: env.CLOUDINARY_API_KEY,
          cloud_name: env.CLOUDINARY_CLOUD_NAME
        });
      }

      // ADD PRODUCT
      if (path === "/api/products" && method === "POST") {
        const body = await request.json();

        if (!validProduct(body)) {
          return json({
            error: "Product name, category and valid price are required."
          }, 400);
        }

        const images = cleanImages(body);
        const id = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO products
          (id, name, description, price, category,
           image_url, image_urls, stock)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id,
          String(body.name).trim(),
          String(body.description || ""),
          Number(body.price),
          String(body.category),
          images[0] || "",
          JSON.stringify(images),
          Math.max(0, Math.floor(Number(body.stock) || 0))
        ).run();

        return json({ success: true, id }, 201);
      }

      const productMatch = path.match(
        /^\/api\/products\/([a-zA-Z0-9-]+)$/
      );

      // EDIT PRODUCT
      if (productMatch && method === "PUT") {
        const body = await request.json();

        if (!validProduct(body)) {
          return json({
            error: "Product name, category and valid price are required."
          }, 400);
        }

        const images = cleanImages(body);

        const result = await env.DB.prepare(`
          UPDATE products
          SET name=?, description=?, price=?,
              category=?, image_url=?, image_urls=?, stock=?
          WHERE id=?
        `).bind(
          String(body.name).trim(),
          String(body.description || ""),
          Number(body.price),
          String(body.category),
          images[0] || "",
          JSON.stringify(images),
          Math.max(0, Math.floor(Number(body.stock) || 0)),
          productMatch[1]
        ).run();

        return json({
          success: true,
          changes: result.meta?.changes || 0
        });
      }

      // DELETE PRODUCT
      if (productMatch && method === "DELETE") {
        await env.DB.prepare(
          "DELETE FROM products WHERE id=?"
        ).bind(productMatch[1]).run();

        return json({ success: true });
      }

      return json({ error: "API route not found." }, 404);

    } catch (error) {
      return json({
        error: "Server error: " + String(error.message || error)
      }, 500);
    }
  }
};
