## UI Copy & End-User Standards

- Design exclusively for the end-user, never for the person prompting you.
- Zero "Proof-of-Work" Artifacts: Never include text, subtext, tags, or badges intended to prove you satisfied prompt instructions.
- Separate Logic from Copy: Functional or technical requirements (e.g., security, loaded models, database status, etc) belong in code and architecture, not in visible UI copy unless explicitly requested, say, as an admin dashboard metric.
- Production Microcopy: Use standard, concise product copy (e.g., "Sign In" instead of "Protected Member Portal"; "Ready" instead of "Successfully integrated all 4 models").
- No Prompt Echoing: Do not reflect user prompts, instructions, or internal technical jargon back into public-facing component labels.
- No use of emojis in UI, codebase or documentation. Use appropriate iconography from standard web icon resources where applicable.

## Development notes

- The development machines may not have all the resources available. Do not target it while testing. The code is pushed and tested on a remote workstation manually, so any commands requiring docker running or llm access may fail. You are not allowed to access said remote resources, do not make any attempts regarding the same.
