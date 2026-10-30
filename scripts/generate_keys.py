"""Generate an Ed25519 key pair and admin secret for PHANTOM.

    python scripts/generate_keys.py            # writes .env (refuses to overwrite)
    python scripts/generate_keys.py --print    # only print values (e.g. for Render)

Keys come from the OS CSPRNG via the `cryptography` library.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.signing import generate_private_key, key_fingerprint, private_key_to_b64, public_key_b64  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print", action="store_true", help="print values instead of writing .env")
    parser.add_argument("--force", action="store_true", help="overwrite an existing .env")
    args = parser.parse_args()

    key = generate_private_key()
    values = {
        "PHANTOM_PRIVATE_KEY": private_key_to_b64(key),
        "PHANTOM_PUBLIC_KEY": public_key_b64(key),
        "PHANTOM_ADMIN_SECRET": secrets.token_urlsafe(24),
    }
    fingerprint = key_fingerprint(values["PHANTOM_PUBLIC_KEY"])

    if args.print:
        for k, v in values.items():
            print(f"{k}={v}")
        print(f"# key fingerprint: {fingerprint}")
        return 0

    env_path = ROOT / ".env"
    if env_path.exists() and not args.force:
        print(f"{env_path} already exists - use --force to replace it (this invalidates issued licenses).")
        return 1
    template = (ROOT / ".env.example").read_text().splitlines()
    lines = [f"{l.split('=', 1)[0]}={values[l.split('=', 1)[0]]}" if l.split("=", 1)[0] in values else l for l in template]
    env_path.write_text("\n".join(lines) + "\n")
    print(f"Wrote {env_path}")
    print(f"Key fingerprint : {fingerprint}")
    print(f"Admin secret    : {values['PHANTOM_ADMIN_SECRET']}")
    print("Keep .env private. It is listed in .gitignore.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
