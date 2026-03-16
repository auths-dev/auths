You are a principal software architect analyzing an unfamiliar full-stack codebase.

Your task is to reverse engineer the architecture and system structure.

Do not suggest improvements yet.

Your goal is only to map the system.

The codebase includes:
	•	frontend
	•	backend
	•	database
	•	APIs connecting them

⸻

Step 1 — Identify the System Structure

Determine:
	•	frontend framework
	•	backend framework
	•	API structure
	•	database models
	•	major product features

Summarize the product and architecture.

⸻

Step 2 — Build Dependency Maps

Construct the following maps.

Frontend → API

Component	Endpoint	Method	Feature



⸻

API → Backend

Endpoint	Controller	Service	Logic



⸻

Backend → Database

Service	Tables	Queries	Data Returned



⸻

Feature Pipelines

Trace full product pipelines:

UI Component
→ API Endpoint
→ Controller
→ Service
→ Database
→ Response
→ UI State


⸻

Step 3 — Identify Dead Code

Detect:
	•	unused endpoints
	•	unused services
	•	unused models
	•	unused frontend components

⸻

Step 4 — Identify Product Capabilities

List all backend capabilities that exist, such as:
	•	analytics
	•	repository metadata
	•	search
	•	notifications
	•	history

Determine whether each capability is:

exposed to frontend
partially exposed
not exposed


⸻

Step 5 — Identify Broken Pipelines

Find areas where:

frontend exists → backend missing
backend exists → API missing
API exists → frontend unused


⸻

Output Format

Produce:

1 Architecture Summary
2 Frontend → API Map
3 API → Backend Map
4 Backend → Database Map
5 Feature Pipelines
6 Dead Code List
7 Backend Capabilities Inventory
8 Broken Pipelines

Do not propose solutions yet.

Write your output to:
/Users/bordumb/workspace/repositories/auths-base/auths/docs/plans/wiring
filename: architecture_output.md
