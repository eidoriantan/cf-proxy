import { env } from "cloudflare:workers";

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin");
    const allowedOrigins = env.ALLOWED_ORIGINS 
      ? env.ALLOWED_ORIGINS.split(",").map(o => o.trim()) 
      : [];

    const allowedAll = allowedOrigins.includes("*");
    const isAllowed = allowedAll || allowedOrigins.includes(origin);
    if (!origin || !isAllowed) {
      return new Response("CORS Forbidden: Origin not allowed.", { status: 403 });
    }

    const url = new URL(request.url);
    let targetUrl = url.search.get("url");
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

    try {
      const response = await fetch(targetUrl, {
        method: request.method,
        headers: request.headers,
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
