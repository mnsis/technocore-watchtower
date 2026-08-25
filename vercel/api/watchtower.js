"use strict";

const BACKEND_ORIGIN = "https://watchtower.37.27.18.191.sslip.io";
const ROUTES = Object.freeze({
  summary: "/api/v1/summary",
  events: "/api/v1/events",
  rooms: "/api/v1/rooms",
  health: "/health",
});
const ROOM_PATTERN = /^[a-z0-9_-]{1,48}$/;

function first(value) {
  return Array.isArray(value) ? value[0] : value;
}

function upstreamUrl(query) {
  const routeName = first(query.route);
  let path = ROUTES[routeName];
  if (routeName === "room") {
    const room = first(query.room);
    if (typeof room !== "string" || !ROOM_PATTERN.test(room)) return null;
    path = `/api/v1/rooms/${encodeURIComponent(room)}`;
  }
  if (!path) return null;

  const url = new URL(path, BACKEND_ORIGIN);
  Object.entries(query).forEach(([name, rawValue]) => {
    if (name === "route" || (routeName === "room" && name === "room")) return;
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    values.forEach((value) => {
      if (typeof value === "string") url.searchParams.append(name, value);
    });
  });
  return url;
}

export default async function handler(request, response) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.setHeader("Allow", "GET, HEAD");
    response.status(405).json({ detail: "Read-only proxy; method not allowed" });
    return;
  }

  const url = upstreamUrl(request.query);
  if (url === null) {
    response.status(404).json({ detail: "Unknown read-only Watchtower route" });
    return;
  }

  try {
    const upstream = await fetch(url, {
      method: request.method,
      headers: { Accept: "application/json" },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(8000),
    });
    response.status(upstream.status);
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Type", upstream.headers.get("content-type") || "application/json");
    if (request.method === "HEAD") {
      response.end();
      return;
    }
    response.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (_) {
    response.status(502).json({ detail: "Watchtower backend temporarily unavailable" });
  }
}
