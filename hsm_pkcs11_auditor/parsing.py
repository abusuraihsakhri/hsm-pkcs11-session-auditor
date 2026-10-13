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


def safe_spreadsheet_cell(value: object) -> object:
    """Escape formula-like CSV text while preserving ordinary numeric cells."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip(" \t\r\n")
    if not stripped or stripped[0] not in "=+-@":
        return value
    if stripped[0] in "+-":
        try:
            import math
            if math.isfinite(float(stripped)):
                return value
        except ValueError:
            pass
    return "'" + value
