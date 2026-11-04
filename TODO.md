# TODO

Open work for Doppel. The unfinished roadmap items that used to sit at the end
of the README live here now; finished features are described in the README.

---

## Features (moved from the README roadmap)

- **External canary token integration.** Doppel issues its own per-session
  decoy credentials and recognises them at `/auth/v1/verify` on the HTTP decoy
  (`doppel/deception/honeytokens.py`, `doppel/http_sensor/sensor.py`). Not yet
  done: optional integration with an external canary service, so use of a
  leaked credential anywhere on the internet is reported, not only use against
  the decoy.
- **Consistency store for generated values.** Per-session honeytokens are
  already stable across a session. Other values the model invents (database
  passwords, internal IPs, file names) can still change between commands.
  Cache them per session and feed them back into later prompts
  (`doppel/ai/deception_engine.py`).
- **Streaming terminal output.** The dashboard assistant and incident reports
  stream, but terminal replies are sent in one piece once generation finishes.
  Streaming long outputs progressively would match how real commands print
  (`LLMClient.chat_completion_stream` exists; `ssh_server.py` would consume it).
- **Webhook alerts.** Email alerts exist (`doppel/alerts/email.py`). Add
  Slack/Discord/generic webhook delivery using the same threshold setting.

## Deployment and verification

- **Build the Ubuntu sandbox image on the workstation.** The image definition
  is `doppel/sandbox/Dockerfile`, built automatically on first use or with
  `python -m doppel.cli build-sandbox`. Not yet tested against a real Docker
  engine. Check that sessions switch from simulated to sandboxed execution once
  the build finishes, and that the container hostname matches the persona.
- **Test `docker compose up`.** Covers the corrected `DOPPEL_SECTION__KEY`
  variables, persistence of `./data` (DB and SSH host keys), and the HTTP decoy
  on 8080.
- **Dashboard inside Docker.** Requests reach the container from the Docker
  gateway address, so the dashboard allowlist must include it. Decide on a
  supported setup (host networking, or a documented allowlist entry) and
  document it.
- **Sandbox bootstrap for non-Ubuntu personas.** The container bootstrap in
  `DockerSandboxManager.create_sandbox_session` writes Ubuntu-specific files and
  paths. With the Debian or Amazon Linux persona selected, sandboxed commands
  that bypass the camouflage layer can still show Ubuntu details.
- **Report load with a real model.** Reports are capped at
  `analytics.max_concurrent_reports` (default 2). Confirm on the GPU machine
  that a burst of short sessions does not slow live replies.
- **Model input from web requests.** Request paths reach the model through the
  HTTP decoy's pseudo-commands. Check with a real model that crafted paths
  cannot make it break persona (`_build_pseudo_command` in the decoy).

## Technical debt

- **Mock mode.** Canned replies in `LLMClient._mock_response` use fixed dates
  and fixed command outputs. Fine for development; avoid relying on mock mode
  for demos of deception quality.
- **Starlette startup hook.** `app.on_event("startup")` is deprecated; move to a
  lifespan handler (`doppel/dashboard/app.py`).
