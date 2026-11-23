"""Generate standards-compliant QR symbols for the active Chat URL."""

from functools import lru_cache

import segno


def generate_qr_matrix(text: str) -> list[list[int]]:
    return [list(row) for row in segno.make(text, error="M", micro=False).matrix]


@lru_cache(maxsize=8)
def generate_qr_svg(text: str, size: int = 240, border: int = 4,
                    bg_color: str = "#ffffff", fg_color: str = "#0f172a") -> str:
    matrix = generate_qr_matrix(text)
    dimension = len(matrix) + 2 * border
    modules = "".join(
        f'<rect x="{column + border}" y="{row + border}" width="1" height="1" fill="{fg_color}"/>'
        for row, cells in enumerate(matrix) for column, filled in enumerate(cells) if filled
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dimension} {dimension}" '
        f'width="{size}" height="{size}" shape-rendering="crispEdges" aria-label="Join QR Code">'
        f'<rect width="100%" height="100%" fill="{bg_color}"/>{modules}</svg>'
    )
