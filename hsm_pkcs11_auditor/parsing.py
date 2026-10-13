"""Shared parsers for CLI and CSV inputs."""

def parse_bool(value: object) -> bool:
    """Parse a CSV boolean without treating the string 'False' as true."""
    if isinstance(value, bool):
        return value
    normalized = str(value if value is not None else "").strip().casefold()
    if normalized in {"true", "1", "yes", "y", "on"}:
        return True
    if normalized in {"false", "0", "no", "n", "off", ""}:
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")
