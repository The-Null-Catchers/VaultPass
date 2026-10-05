import argparse

from .mailer import deliver_email


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send one VaultPass transactional email through the configured SMTP provider."
    )
    parser.add_argument("--recipient", required=True, help="Inbox that should receive the smoke email")
    args = parser.parse_args()

    deliver_email(
        args.recipient,
        "VaultPass email delivery smoke test",
        "This is a VaultPass release-readiness SMTP delivery test. "
        "No vault contents or secrets are included in this message.",
    )
    print(
        "SMTP provider accepted the VaultPass smoke message. "
        "Confirm inbox receipt, sender identity, TLS/provider logs, and spam placement manually."
    )


if __name__ == "__main__":
    main()
