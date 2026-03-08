from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))


def current_utc_time() -> datetime:
    """Returns the current UTC time."""
    return datetime.now(timezone.utc)


def now_ist() -> datetime:
    """Returns the current time in Asia/Kolkata (IST)."""
    return datetime.now(IST)


def now_ist_naive() -> datetime:
    """Current time in IST as naive datetime for comparing with SQLite datetime columns."""
    return datetime.now(IST).replace(tzinfo=None)


def utc_timestamp() -> int:
    """Returns the current UTC timestamp."""
    return int(current_utc_time().timestamp())


def format_time(dt: datetime) -> str:
    """Format datetime to readable string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_time(timestr: str) -> datetime:
    """Convert string to datetime object."""
    return datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S")
