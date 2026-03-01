  Here's why that's the right target.                                                                                                  
                                                                                                                                       
  What will land well:                                                                                                                 
  - Most local-first developers have hit the OAuth wall and know it's a problem. You're showing a working solution, not just describing
   one. That's valuable.
  - Git-as-storage is immediately legible to this audience. They'll intuit why it works for local-first.
  - The WASM portability story (same verifier in CLI, browser, mobile) is a concrete engineering win people can steal for their own
  projects.

  What won't feel revolutionary:
  - Self-sovereign identity is a 10-year-old idea. The audience has heard the pitch from SSI, Solid, Keybase, various Web3 projects.
  Many are cynical about it. Your job is to overcome that cynicism with working software, not bigger claims.
  - KERI itself has been presented at identity conferences since ~2019. The novelty is your Git-native adaptation and the local-first
  framing, not the underlying concept.
  - The "no blockchain" positioning is a relief, not a surprise. This audience already agrees blockchains are overkill for identity.

  The real value is practical, not theoretical:

  The talks that stick at these conferences aren't the ones with the grandest vision — they're the ones where someone says "I built it,
   here's what broke, here's the architecture, here's what I'd do differently." Your strongest material is:

  1. The specific CAS/conflict-resolution decisions you made for concurrent device authority
  2. What went wrong when you tried to make crypto portable to WASM (every local-first dev shipping to browsers will relate)
  3. The actual DX of auths init → sign → verify across devices with no server

  Calibration advice:

  Position as "the identity problem is solved, here's proof" not "I have a revolutionary new paradigm." The former earns trust; the
  latter invites skepticism. A talk that sends 50 developers home thinking "I could actually replace OAuth in my app with something
  like this" is worth more than one that gets a standing ovation and no adoption.

  