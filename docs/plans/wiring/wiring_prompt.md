You are a principal product engineer and system architect.

You previously analyzed this system and generated an architecture report.
path: /Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/wiring/architecture_output.md

Use the architecture analysis below to propose product-driven engineering improvements.

Important context:
	•	The product currently has zero users
	•	Large refactors are allowed
	•	Backward compatibility is not required
	•	The goal is a cleaner architecture and better frontend product experience


core logic: /Users/bordumb/workspace/repositories/auths-base/auths
frontend: /Users/bordumb/workspace/repositories/auths-base/auths-site
backend: /Users/bordumb/workspace/repositories/auths-base/auths-cloud/ mostly crate/{auths-auth-server, auths-registry-server}

⸻

Step 1 — Product Experience Analysis

Evaluate how the architecture affects the frontend product.

Ask:
	•	Are backend capabilities visible to users?
	•	Are APIs optimized for UI needs?
	•	Are there product features blocked by architecture?

⸻

Step 2 — Identify Improvement Opportunities

Look for:
	•	backend capabilities not surfaced
	•	missing feature pipelines
	•	inefficient APIs
	•	overly complex architecture
	•	dead code

⸻

Step 3 — Generate Engineering Epics

Group improvements into epics.

Example:

Epic: Expose Repository Analytics to Frontend
Epic: Simplify Repository Data Pipeline
Epic: Remove Dead Backend Services
Epic: Consolidate Duplicate API Endpoints


⸻

Step 4 — Generate Implementation Tasks

Each task must include:

Task Title
Repository
Files to modify
Current code
Improved code
Explanation

Example:

Repository

backend

Files

backend/src/controllers/repoController.ts

Current code

return { id, name }

Improved code

return {
  id,
  name,
  analytics: repoAnalytics
}

Explanation

Describe the product and architecture benefit.

⸻

Step 5 — Prioritize Work

Organize tasks into:

Critical
High
Medium
Low


Write your output to:
/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/wiring
filename: wiring_output.md
