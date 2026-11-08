## UI Copy & End-User Standards

- Design exclusively for the end-user, never for the person prompting you.
- Zero "Proof-of-Work" Artifacts: Never include text, subtext, tags, or badges intended to prove you satisfied prompt instructions.
- Separate Logic from Copy: Functional or technical requirements (e.g., security, loaded models, database status, etc) belong in code and architecture, not in visible UI copy unless explicitly requested, say, as an admin dashboard metric.
- Production Microcopy: Use standard, concise product copy (e.g., "Sign In" instead of "Protected Member Portal"; "Ready" instead of "Successfully integrated all 4 models").
- No Prompt Echoing: Do not reflect user prompts, instructions, or internal technical jargon back into public-facing component labels.
- No use of emojis in UI, codebase or documentation. Use appropriate iconography from standard web icon resources where applicable.

## Development notes

- The development machines may not have all the resources available. The code is pushed and tested on a remote workstation manually, so any commands requiring docker running or llm access may fail.

- You can access the dashboard on `100.100.186.40`, IF required. Always ask the user permission before accessing the dashboard, and confirm from them if it is even running in the first place, and if the latest code is running on it.

## Testing on the workstation

- Test locally when the change does not need the model or Docker: UI changes, dashboard copy and layout, pure Python logic, and `pytest` (the LLM client's mock mode needs no model).
- Test on the workstation when the change touches the model, Docker, routing outcomes or anything end to end: deception output, the grounded tier, sandbox behaviour, tagging, reports.
- The workstation is shared. Being able to reach it does not mean it is free to use. Before using it, ask the user to confirm in the team group that:
  1. nobody else is testing on it right now,
  2. Doppel is running, and
  3. it runs the commit you need (ask which one).
- Once the user confirms, you may run the tests yourself instead of asking the user to do it, to speed up bug fixes:
  - Dashboard and control API: `http://100.100.186.40:8000`. Endpoints are in [docs/dashboard.md](docs/dashboard.md#control-api), and the interactive reference is at `/docs`.
  - SSH honeypot: port `2222`. HTTP decoy: port `8080`.
- Note every setting you change through the API, and restore it when you finish. That includes the model, `auto_reports` and timeouts.
- Stop and tell the user if you see sessions you did not start, or the analysis queue busy with work that is not yours. Someone else is probably testing.
- Never deploy or restart Doppel on the workstation. The user does that.
