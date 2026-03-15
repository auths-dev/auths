// Cloudflare Worker that serves the auths install script at get.auths.dev
//
// Deploy:
//   cd deploy/get-auths-dev
//   npx wrangler deploy
//
// The worker fetches install.sh from the main branch on GitHub and
// caches it at the edge for 5 minutes so updates propagate quickly.

const SCRIPT_URL =
  "https://raw.githubusercontent.com/auths-dev/auths/main/scripts/install.sh";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    // Serve install script for root path (what curl hits)
    if (url.pathname === "/" || url.pathname === "") {
      const cached = await caches.default.match(request);
      if (cached) return cached;

      const upstream = await fetch(SCRIPT_URL, {
        headers: { "User-Agent": "get-auths-dev-worker" },
      });

      if (!upstream.ok) {
        return new Response("Failed to fetch install script", { status: 502 });
      }

      const body = await upstream.text();
      const response = new Response(body, {
        headers: {
          "Content-Type": "application/x-sh",
          "Cache-Control": "public, max-age=300",
        },
      });

      const ctx = { waitUntil: (p) => p };
      try {
        await caches.default.put(request, response.clone());
      } catch (_) {
        // Edge cache put can fail in local dev
      }

      return response;
    }

    // Anything else: redirect to docs
    return Response.redirect("https://auths.dev/docs/getting-started", 302);
  },
};
