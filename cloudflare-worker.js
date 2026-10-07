/**
 * PFD Companion — reverse-proxy Worker.
 *
 * Replaces a redirect-based Worker (302 to the current ephemeral
 * *.trycloudflare.com host) with a transparent proxy. The difference matters
 * for one reason: a redirect changes the browser's address bar to the
 * ephemeral tunnel host, so anything that pins that URL — most importantly
 * iOS "Add to Home Screen" — breaks the next time the bridge restarts and
 * cloudflared hands out a new random hostname. A proxy never changes the
 * address bar at all: the browser always talks to this Worker's own fixed
 * hostname, and this Worker fetches from whatever backend is currently
 * registered. The home-screen bookmark becomes permanent.
 *
 * Deployment (one-time):
 *   1. Cloudflare dashboard → Workers & Pages → the "pfd-companion" Worker
 *      → Edit code → replace its contents with this file → Save & Deploy.
 *   2. Create a KV namespace (Workers & Pages → KV → Create) — any name is
 *      fine, e.g. "pfd-tunnel". Bind it to this Worker as TUNNEL_KV
 *      (Settings → Variables → KV Namespace Bindings → variable name
 *      TUNNEL_KV → your namespace).
 *   3. Settings → Variables and Secrets → add a Secret named UPDATE_SECRET.
 *      Set its value to the exact contents of auth_token.txt from the PC
 *      running the bridge (same file msfs_bridge.py already generates).
 *      This is what stops a stranger from pointing your public URL at their
 *      own server — without it, anyone could call /update?url=... and every
 *      future visit to your bookmark would silently proxy to them instead.
 *   4. Save & Deploy again if the bindings didn't trigger a redeploy.
 *
 * launch_pfd.ps1 already calls "$WorkerUrl/update?url=$url" on every launch,
 * with the secret sent as an X-Update-Secret header rather than a query-
 * string param (so it can't end up cached/logged by an intermediate proxy or
 * Cloudflare's own edge access logs) — no changes needed there once this is
 * deployed.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/update") {
      const secret = request.headers.get("X-Update-Secret") || "";
      if (!env.UPDATE_SECRET || secret !== env.UPDATE_SECRET) {
        return new Response("unauthorized", { status: 403 });
      }
      const target = url.searchParams.get("url") || "";
      if (!/^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/i.test(target)) {
        return new Response("bad url", { status: 400 });
      }
      await env.TUNNEL_KV.put("backend_url", target);
      return new Response("ok");
    }

    const backend = await env.TUNNEL_KV.get("backend_url");
    if (!backend) {
      return new Response(
        "No bridge is currently registered. Launch PFD Companion on your PC first.",
        { status: 502 }
      );
    }

    const target = new URL(backend);
    target.pathname = url.pathname;
    target.search = url.search;

    // Request(url, request) copies method/headers/body (including the
    // Upgrade/Connection headers a WebSocket handshake needs) from the
    // original request, overriding only the destination — this is the
    // standard Cloudflare Workers proxying idiom and transparently handles
    // both plain HTTP and the /ws WebSocket upgrade.
    return fetch(new Request(target.toString(), request));
  },
};
