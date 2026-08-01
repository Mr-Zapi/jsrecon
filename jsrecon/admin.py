"""Admin CLI.

Registration is now open-on-first-run (the first account created via the UI
becomes the owner; after that registration is closed), so one-time codes are
gone. This command just reports the current auth state.

    python -m jsrecon.admin status
"""
from __future__ import annotations

import sys

from . import auth, store


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    store.init()
    owner = store.first_user()
    print(f"data dir:  {store.DATA_DIR}")
    print(f"api token: {auth.TOKEN}  (stored in {store.DATA_DIR}/token)")
    if owner:
        print(f"owner:     {owner}  (registration closed)")
    else:
        print("owner:     none yet - register the first account in the UI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
