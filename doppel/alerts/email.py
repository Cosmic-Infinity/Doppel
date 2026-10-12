import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, Optional, Set

logger = logging.getLogger("doppel.alerts.email")


class EmailAlerter:
    """Asynchronous background email alerting service for honeypot threat events."""

    def __init__(
        self,
        enabled: bool = False,
        smtp_server: str = "smtp.example.com",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        use_tls: bool = True,
        sender_email: str = "doppel@example.com",
        receiver_email: str = "alerts@example.com",
        min_threat_score: int = 60,
    ):
        self.enabled = enabled
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.sender_email = sender_email
        self.receiver_email = receiver_email
        self.min_threat_score = min_threat_score

        # Track alerted sessions to avoid spamming alerts on every subsequent keystroke
        self._alerted_sessions: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    def should_alert(self, session_id: str, threat_score: int) -> bool:
        """Evaluate if an email alert should be triggered for this session."""
        if not self.enabled:
            return False

        if threat_score < self.min_threat_score:
            return False

        last_alerted_score = self._alerted_sessions.get(session_id, 0)
        # Alert if never alerted or if threat score escalated by at least 25 points
        if last_alerted_score == 0 or (threat_score - last_alerted_score) >= 25:
            return True

        return False

    async def maybe_send_alert(
        self,
        session_id: str,
        remote_ip: str,
        threat_score: int,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Asynchronously evaluate and send an alert without blocking caller execution."""
        if not self.should_alert(session_id, threat_score):
            return

        async with self._lock:
            # Recheck under lock to prevent race conditions across parallel command observer tasks
            if not self.should_alert(session_id, threat_score):
                return
            self._alerted_sessions[session_id] = threat_score

        # Fire and forget asynchronously
        asyncio.create_task(
            self._dispatch_email_task(session_id, remote_ip, threat_score, details or {})
        )

    async def _dispatch_email_task(
        self,
        session_id: str,
        remote_ip: str,
        threat_score: int,
        details: Dict[str, Any],
    ):
        """Run blocking SMTP operations in a dedicated thread pool worker."""
        try:
            await asyncio.to_thread(
                self._send_sync_email, session_id, remote_ip, threat_score, details
            )
            logger.info(
                f"Dispatched high-threat email alert for session {session_id[:8]} (IP: {remote_ip}, Score: {threat_score})"
            )
        except Exception as err:
            logger.error(
                f"Failed to dispatch email alert for session {session_id[:8]} to {self.receiver_email}: {err}",
                exc_info=False,
            )

    def _send_sync_email(
        self,
        session_id: str,
        remote_ip: str,
        threat_score: int,
        details: Dict[str, Any],
    ):
        """Synchronous SMTP worker invoked via asyncio.to_thread."""
        subject = f"[DOPPEL ALERT] High Threat Activity ({threat_score}/100) from {remote_ip}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = self.receiver_email

        techniques = details.get("techniques", [])
        technique_str = ", ".join(techniques) if techniques else "Unclassified Reconnaissance"
        last_command = details.get("last_command", "N/A")
        username = details.get("username", "ubuntu")
        geo_str = details.get("geo_summary", "Unknown location")

        text_content = (
            f"Doppel Honeypot Threat Alert\n"
            f"-----------------------------\n"
            f"Attacker IP:    {remote_ip}\n"
            f"Location:       {geo_str}\n"
            f"Session ID:     {session_id}\n"
            f"User Target:    {username}\n"
            f"Threat Score:   {threat_score} / 100\n"
            f"Techniques:     {technique_str}\n"
            f"Last Command:   {last_command}\n\n"
            f"Inspect live telemetry in the Doppel Web SOC dashboard."
        )

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; padding: 24px; }}
            .header {{ border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }}
            .title {{ font-size: 18px; font-weight: 700; color: #f43f5e; margin: 0; }}
            .score-badge {{ display: inline-block; padding: 4px 10px; background: rgba(244, 63, 94, 0.15); border: 1px solid #f43f5e; color: #f43f5e; font-weight: 700; border-radius: 4px; font-size: 14px; margin-top: 8px; }}
            .item {{ margin-bottom: 12px; }}
            .label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }}
            .value {{ font-size: 14px; font-family: monospace; color: #f8fafc; margin-top: 2px; }}
            .cmd-block {{ background: #0b0f19; padding: 10px 14px; border-radius: 6px; font-family: monospace; color: #00f5d4; border: 1px solid #1e293b; }}
            .footer {{ margin-top: 24px; padding-top: 16px; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h2 class="title">Security Threat Alert</h2>
              <div class="score-badge">Threat Score: {threat_score} / 100</div>
            </div>
            <div class="item">
              <div class="label">Attacker Remote IP</div>
              <div class="value">{remote_ip} ({geo_str})</div>
            </div>
            <div class="item">
              <div class="label">Target Session</div>
              <div class="value">{session_id} (user: {username})</div>
            </div>
            <div class="item">
              <div class="label">MITRE ATT&CK Attribution</div>
              <div class="value">{technique_str}</div>
            </div>
            <div class="item">
              <div class="label">Last Executed Command</div>
              <div class="cmd-block">{last_command}</div>
            </div>
            <div class="footer">
              Generated automatically by Doppel AI-Augmented Hybrid Honeypot System.
            </div>
          </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        if self.use_tls:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=15)

        if self.smtp_user and self.smtp_password:
            server.login(self.smtp_user, self.smtp_password)

        server.sendmail(self.sender_email, [self.receiver_email], msg.as_string())
        server.quit()
