"""
main.py

CLI tool to:
 - check password strength (optionally check HIBP)
 - generate password (options)
 - send generated password to Slack (via env var)

Usage examples:
  python main.py check --password "MyP@ssw0rd!"
  python main.py generate --length 18 --no-symbols --slack
"""

import argparse
import os
import sys

from password_utils import evaluate_password, generate_password
from hibp import check_sha1_in_hibp
from slack_integration import send_to_slack_via_webhook, send_to_slack_via_bot_token

def load_env_vars():
    """
    Load env vars from process. If you use a .env file, use dotenv in your environment,
    or export variables before running.
    """
    return {
        "SLACK_WEBHOOK_URL": os.getenv("SLACK_WEBHOOK_URL"),
        "SLACK_BOT_TOKEN": os.getenv("SLACK_BOT_TOKEN"),
        "SLACK_CHANNEL_ID": os.getenv("SLACK_CHANNEL_ID"),
    }

def do_check(args):
    password = args.password
    if password is None:
        # read from stdin securely
        import getpass
        password = getpass.getpass(prompt="Enter password to check (input hidden): ")

    # If user wants hibp check, provide function wrapper to keep separation
    hibp_check_fn = None
    if args.hibp:
        def _hibp_fn(sha1_upper):
            return check_sha1_in_hibp(sha1_upper)
        hibp_check_fn = _hibp_fn

    result = evaluate_password(password, min_length=args.min_length, check_breach=args.hibp, hibp_check_fn=hibp_check_fn)
    # Print safe summary (do not print raw password)
    print("OK:", result["ok"])
    print("Score:", result["score"])
    for r in result["reasons"]:
        print("-", r)
    # Optionally return nonzero code if failure
    if not result["ok"]:
        sys.exit(2)

def do_generate(args):
    pwd = generate_password(length=args.length, no_symbols=args.no_symbols)
    # We purposely do not print the password to standard logs if --quiet is set.
    if not args.quiet:
        print("Generated password (displaying once):")
        print(pwd)
    else:
        print("Password generated (suppressed display due to --quiet).")

    # If user requested to send to Slack
    if args.slack:
        env = load_env_vars()
        sent = False
        slack_text = f"Secret password (generated) — keep secure: `{pwd}`"
        # Prefer webhook if provided
        if env["SLACK_WEBHOOK_URL"]:
            try:
                sent = send_to_slack_via_webhook(env["SLACK_WEBHOOK_URL"], slack_text)
            except Exception as e:
                print("Failed to send via webhook:", e)
                sent = False
        elif env["SLACK_BOT_TOKEN"] and env["SLACK_CHANNEL_ID"]:
            sent = send_to_slack_via_bot_token(env["SLACK_BOT_TOKEN"], env["SLACK_CHANNEL_ID"], slack_text)
        else:
            print("Slack not configured. Set SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN + SLACK_CHANNEL_ID in environment.")
        # For security, do not print password back out as verification. Only report success.
        if sent:
            print("Password sent to Slack successfully (not shown).")
        else:
            print("Failed to send password to Slack.")

def main():
    parser = argparse.ArgumentParser(prog="metron-security", description="Password strength and distribution utility")
    sub = parser.add_subparsers(dest="command")

    # check subcommand
    p_check = sub.add_parser("check", help="Check strength of a password")
    p_check.add_argument("--password", "-p", type=str, help="Password to check (if omitted, reads hidden input)")
    p_check.add_argument("--min-length", type=int, default=12, help="Minimum allowed length")
    p_check.add_argument("--hibp", action="store_true", help="Check HIBP breach database (uses k-anonymity)")

    # generate subcommand
    p_gen = sub.add_parser("generate", help="Generate a strong password")
    p_gen.add_argument("--length", type=int, default=16, help="Password length (16-24)")
    p_gen.add_argument("--no-symbols", action="store_true", help="Do not include symbols")
    p_gen.add_argument("--quiet", action="store_true", help="Do not print password to standard output")
    p_gen.add_argument("--slack", action="store_true", help="Send generated password to Slack (configured via env vars)")

    args = parser.parse_args()
    if args.command == "check":
        do_check(args)
    elif args.command == "generate":
        do_generate(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
