// Vercel Edge Function that serves the auths install script at get.auths.dev
//
// The auths.dev zone is on Vercel DNS (it hosts the main site), so the
// installer is hosted there too — adding the get.auths.dev domain to this
// project auto-creates the DNS record. See README.md for deploy steps.
//
// Fetches install.sh from the main branch on GitHub and caches it at the
// edge for 5 minutes so updates propagate quickly.

export const config = { runtime: "edge" };

const SCRIPT_URL =
  "https://raw.githubusercontent.com/auths-dev/auths/main/scripts/install.sh";

export default async function handler(request) {
  const path = new URL(request.url).searchParams.get("path") ?? "";

  if (path === "health") {
    return new Response("ok", { status: 200 });
  }

  if (path === "") {
    const upstream = await fetch(SCRIPT_URL, {
      headers: { "User-Agent": "get-auths-dev" },
    });

    if (!upstream.ok) {
      return new Response("Failed to fetch install script", { status: 502 });
    }

    return new Response(await upstream.text(), {
      headers: {
        "Content-Type": "application/x-sh",
        "Cache-Control": "public, max-age=300, s-maxage=300",
      },
    });
  }

  return Response.redirect("https://auths.dev/docs/getting-started", 302);
}
