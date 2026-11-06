"""
Simulated host clock.

Everything an attacker sees that carries a date, time or duration is derived
from here, so output always agrees with the real current time instead of a
fixed snapshot:

  - the current time is the real UTC time;
  - the boot time is "now minus the persona's uptime", anchored once per
    process so uptime keeps counting naturally while Doppel runs;
  - durations of scans and tool runs are drawn from a range, so repeated runs
    never report identical timings.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

_PROCESS_START = datetime.now(timezone.utc)

# How long each persona's server has been up when Doppel starts
PERSONA_UPTIME = {
    "ubuntu_web_server": timedelta(days=43, hours=7, minutes=22),
    "cloud_worker": timedelta(days=12, hours=4, minutes=51),
    "fintech_api": timedelta(days=8, hours=15, minutes=3),
}
_DEFAULT_UPTIME = PERSONA_UPTIME["ubuntu_web_server"]
_active_persona = "ubuntu_web_server"

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def set_persona(persona: str) -> None:
    global _active_persona
    if persona:
        _active_persona = persona


def now() -> datetime:
    return datetime.now(timezone.utc)


def boot_time(persona: Optional[str] = None) -> datetime:
    uptime = PERSONA_UPTIME.get(persona or _active_persona, _DEFAULT_UPTIME)
    return (_PROCESS_START - uptime).replace(microsecond=0)


def uptime(persona: Optional[str] = None) -> timedelta:
    return now() - boot_time(persona)


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------- formats
def ctime(dt: datetime) -> str:
    """'Thu Aug 30 17:08:22 2026' (ctime, space-padded day)."""
    return f"{_DAYS[dt.weekday()]} {_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S} {dt.year}"


def short_date(dt: datetime) -> str:
    """'Thu Aug 30 17:08' as used by last(1)."""
    return f"{_DAYS[dt.weekday()]} {_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M}"


def ls_time(dt: datetime, ref: Optional[datetime] = None) -> str:
    """GNU ls -l timestamp: time for files under six months old, year otherwise."""
    ref = ref or now()
    if abs((ref - dt).days) < 182:
        return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M}"
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d}  {dt.year}"


def ps_start(dt: datetime, ref: Optional[datetime] = None) -> str:
    """ps START column: HH:MM today, MmmDD this year, the year otherwise."""
    ref = ref or now()
    if dt.date() == ref.date():
        return f"{dt:%H:%M}"
    if dt.year == ref.year:
        return f"{_MONTHS[dt.month - 1]}{dt.day:02d}"
    return str(dt.year)


def uptime_text(persona: Optional[str] = None) -> str:
    """'43 days,  7:22' as printed by uptime(1)."""
    up = uptime(persona)
    days, rest = up.days, up.seconds
    hours, minutes = rest // 3600, (rest % 3600) // 60
    hm = f"{hours:2d}:{minutes:02d}" if hours else f"{minutes} min"
    if days:
        return f"{days} day{'s' if days != 1 else ''}, {hm}"
    return hm


def load_average() -> str:
    a = random.uniform(0.05, 0.35)
    return f"{a:.2f}, {a * random.uniform(0.8, 1.4):.2f}, {a * random.uniform(0.7, 1.2):.2f}"


def uptime_line(persona: Optional[str] = None, users: int = 1) -> str:
    return (f" {now():%H:%M:%S} up {uptime_text(persona)},  {users} user{'s' if users != 1 else ''},"
            f"  load average: {load_average()}")


def days_ago_since(dt: datetime) -> str:
    """'43 days ago' / '7h ago' as in systemctl status."""
    delta = now() - dt
    if delta.days >= 1:
        return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"
    hours = delta.seconds // 3600
    return f"{hours}h ago" if hours else f"{delta.seconds // 60}min ago"


# ---------------------------------------------------------------- durations
def duration(low: float, high: float) -> float:
    """A run time in seconds that varies naturally between calls."""
    return round(random.triangular(low, high, low + (high - low) * 0.35), 2)


def run_window(low: float, high: float) -> Tuple[datetime, datetime, float]:
    """(start, end, seconds) for a tool run that has just finished."""
    secs = duration(low, high)
    end = now()
    return end - timedelta(seconds=secs), end, secs
