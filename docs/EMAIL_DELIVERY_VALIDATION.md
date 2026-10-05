# Real email delivery validation

VaultPass security-email code is covered by automated tests, but a production release still needs one real-provider delivery check with the exact SMTP account, sender identity and DNS configuration intended for deployment.

## Configure the provider

Use deployment secrets rather than committing credentials. Required settings are:

```env
ENVIRONMENT=production
SMTP_HOST=smtp.provider.example
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
MAIL_FROM=VaultPass <security@example.com>
```

Production SMTP delivery uses STARTTLS with the platform trust store and authenticates only when `SMTP_USERNAME` is configured.

## Send the bounded smoke message

From the backend environment that has the real SMTP secrets loaded:

```bash
python -m app.email_smoke --recipient release-test@example.com
```

The command sends a fixed release-readiness message. It does not read vault items and does not include vault plaintext, ciphertext, recovery material, tokens or passwords.

A successful command means the SMTP provider accepted the message. It does **not** by itself prove inbox delivery.

## Evidence to record before release

Record the date, deployment/environment identifier and provider message/event identifier outside the repository. Confirm all of the following:

- the intended inbox receives the message;
- the visible From address is the configured VaultPass sender;
- the provider reports TLS for the SMTP submission;
- SPF, DKIM and DMARC results are acceptable for the deployment domain;
- the message is not routed to spam for the validation inbox;
- a real additional-device sign-in produces the `New VaultPass sign-in` email when the account preference is enabled;
- disabling the preference prevents the additional-device security email;
- initial registration does not produce the new-device alert.

Do not paste SMTP credentials, account tokens, vault data or full provider logs containing sensitive metadata into GitHub issues or release notes.

## Release gate

Keep the release-readiness gate open until the real-provider smoke message and one end-to-end additional-device sign-in email have both been observed in the destination inbox using the production-intended provider configuration.
