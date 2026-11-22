import os
import subprocess
import sys

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def shot(url: str, out: str, width: int = 1600, height: int = 1250, budget: int = 6000) -> int:
    args = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        f"--window-size={width},{height}",
        f"--virtual-time-budget={budget}",
        f"--user-data-dir={os.path.join(os.environ['TEMP'], 'chrome-shot-prof')}",
        f"--screenshot={out}",
        url,
    ]
    p = subprocess.run(args, capture_output=True, timeout=90)
    return p.returncode


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765/"
    out = sys.argv[2] if len(sys.argv) > 2 else r"D:\huaweinet\console\samples\ui.png"
    w = int(sys.argv[3]) if len(sys.argv) > 3 else 1600
    h = int(sys.argv[4]) if len(sys.argv) > 4 else 1250
    rc = shot(url, out, w, h)
    size = os.path.getsize(out) if os.path.exists(out) else 0
    print(f"rc={rc} out={out} size={size}")
