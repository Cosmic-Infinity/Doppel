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
- **Streaming terminal output.** The dashboard assistant and incident reports
  stream, but terminal replies are sent in one piece once generation finishes.
  Streaming long outputs progressively would match how real commands print
  (`LLMClient.chat_completion_stream` exists; `ssh_server.py` would consume it).
- **Webhook alerts.** Email alerts exist (`doppel/alerts/email.py`). Add
  Slack/Discord/generic webhook delivery using the same threshold setting.

## Deployment and verification

- **Test `docker compose up`.** Covers the corrected `DOPPEL_SECTION__KEY`
  variables, persistence of `./data` (DB and SSH host keys), and the HTTP decoy
  on 8080.
- **Dashboard inside Docker.** Requests reach the container from the Docker
  gateway address, so the dashboard allowlist must include it. Decide on a
  supported setup (host networking, or a documented allowlist entry) and
  document it.
- **Report load with a real model.** Reports are capped at
  `analytics.max_concurrent_reports` (default 2). Confirm on the GPU machine
  that a burst of short sessions does not slow live replies.
- **Model input from web requests.** Request paths reach the model through the
  HTTP decoy's pseudo-commands. Check with a real model that crafted paths
  cannot make it break persona (`_build_pseudo_command` in the decoy).

## Technical debt

- **Mock mode.** Canned replies in `LLMClient._mock_response` follow the
  simulated clock but are fixed command outputs. Fine for development; avoid
  relying on mock mode for demos of deception quality.
