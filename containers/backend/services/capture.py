import io
import requests
import logging
from PIL import Image, ImageDraw

logger = logging.getLogger(__name__)

# Max payload sizes to prevent memory exhaustion, same as stage2
_MAX_HTML_BYTES = 10 * 1024 * 1024

def capture_url(url: str) -> tuple[bytes, str]:
    """
    Lightweight capture: fetch HTML via requests, generate a minimal
    placeholder screenshot (white 1366x768 PNG with URL text stamped).
    
    Limitation vs. extension:
    - Screenshot is NOT a real render — it's a visual placeholder.
    - HTML IS the real fetched DOM.
    - The sandbox (Stage 5) still sees the REAL page independently.
    
    Returns: (png_bytes, html_content)
    """
    html_content = ""
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, stream=True)
        # Prevent downloading massive non-HTML files
        raw_bytes = resp.raw.read(_MAX_HTML_BYTES + 1)
        if len(raw_bytes) > _MAX_HTML_BYTES:
            logger.warning("URL %s exceeded _MAX_HTML_BYTES, truncating.", url)
            
        # Attempt to decode as text
        encoding = resp.encoding or "utf-8"
        try:
            html_content = raw_bytes.decode(encoding, errors="replace")
        except LookupError:
            html_content = raw_bytes.decode("utf-8", errors="replace")
            
    except Exception as e:
        logger.warning("capture_url failed to fetch %s: %s", url, e)
        html_content = f"<html><body>Failed to fetch: {e}</body></html>"

    # Create a 1366x768 placeholder image
    img = Image.new("RGB", (1366, 768), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    
    # Try to load a default font, otherwise Pillow uses a basic one
    draw.text((50, 50), f"Captured server-side without extension: {url}", fill=(0, 0, 0))
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    
    return png_bytes, html_content
