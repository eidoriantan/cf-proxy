import { env } from "cloudflare:workers";

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin");
    const allowedOrigins = env.ALLOWED_ORIGINS
      ? env.ALLOWED_ORIGINS.split(",").map(o => o.trim())
      : [];

    const allowedAll = allowedOrigins.includes("*");
    const isAllowed = allowedAll || allowedOrigins.includes(origin);
    if (!isAllowed) {
      return new Response("CORS Forbidden: Origin not allowed.", { status: 403 });
    }

    const url = new URL(request.url);
    let targetUrl = url.searchParams.get("url");
    if (!targetUrl) {
      return new Response("Send a request like: ?url=https://example.com", { status: 400 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers") || "*",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // --- Rate limiting (per client IP) ---
    // Runs after the origin check and OPTIONS handling, so preflights and
    // disallowed origins don't consume quota.
    if (env.RATE_LIMITER) {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const { success } = await env.RATE_LIMITER.limit({ key: clientIp });
      if (!success) {
        // CORS headers are included so the browser can read the 429
        // instead of surfacing an opaque CORS error.
        return new Response("Too Many Requests: slow down and retry shortly.", {
          status: 429,
          headers: {
            "Retry-After": "60",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
          },
        });
      }
    }

    const newReqHeaders = new Headers();
    for (const [name, value] of request.headers.entries()) {
      if (name.toLowerCase().startsWith("x-proxy-")) {
        const originalHeaderName = name.substring(8);
        newReqHeaders.set(originalHeaderName, value);
      } else {
        newReqHeaders.set(name, value);
      }
    }

    try {
      const response = await fetch(targetUrl, {
        method: request.method,
        headers: newReqHeaders,
        body: request.body,
        redirect: request.redirect,
      });

      const newHeaders = new Headers(response.headers);
      newHeaders.set("Access-Control-Allow-Origin", origin);
      newHeaders.set("Access-Control-Allow-Credentials", "true");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    } catch (err) {
      return new Response("Proxy error: " + err.message, { status: 500 });
    }
  },
};
