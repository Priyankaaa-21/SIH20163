import os
import sys

# Add repo root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.poc.poc_open_registration import run_open_registration_poc
from backend.poc.poc_token_expiration import run_token_expiration_poc
from backend.poc.poc_non_admin_post import run_non_admin_post_poc
from backend.poc.poc_login_lockout import run_login_lockout_poc

def main():
    print("=" * 80)
    print(" SIH 26163 — AUTOMATED PROOF OF CONCEPT (PoC) VERIFICATION SUITE")
    print("=" * 80)
    print("Executing all Before/After test harnesses against baseline and hardened implementations...\n")

    pocs = [
        ("Open User Registration", run_open_registration_poc),
        ("Missing Token Expiration", run_token_expiration_poc),
        ("Non-Admin State Modification", run_non_admin_post_poc),
        ("Account Lockout Protection", run_login_lockout_poc)
    ]

    results = []
    for name, func in pocs:
        try:
            success = func()
            results.append((name, "PASSED" if success else "FAILED"))
        except Exception as e:
            print(f"[!] Error executing PoC {name}: {e}")
            results.append((name, f"ERROR: {e}"))

    print("\n" + "=" * 80)
    print(" PROOF OF CONCEPT EXECUTION SUMMARY")
    print("=" * 80)
    for name, status in results:
        print(f" - {name:<35} : [{status}]")
    print("=" * 80)

    # Return non-zero if any failed
    if any(status != "PASSED" for _, status in results):
        sys.exit(1)
    else:
        print("[✓] All 4 PoC proofs executed successfully with evidence recorded in database.")
        sys.exit(0)

if __name__ == "__main__":
    main()
