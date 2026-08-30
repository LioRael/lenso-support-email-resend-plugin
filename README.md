# lenso.support-email.resend

`lenso.support-email.resend` turns verified Resend inbound email into Support
Intake calls. It is a removable channel adapter: Customer Directory owns the
sender identity and Support Case owns cases, messages, revisions, and
idempotency receipts.

## Flow

1. `POST /webhooks/resend` rejects oversized, stale, or invalid Svix-signed
   requests. Verification uses the exact raw body and `svix-id`,
   `svix-timestamp`, and `svix-signature` headers.
2. `email.received` metadata is followed by an authenticated
   `GET /emails/receiving/{email_id}` through `lenso.http.client@1`; webhook
   metadata is never mistaken for the full message.
3. The sender is resolved through `lenso.customer-directory@1`.
4. Mail to a configured base address opens a case through
   `lenso.support-intake@1`. Thread continuation requires
   `local+SUP-42.<token>@domain`, where `<token>` is a full HMAC-SHA256 bearer
   token bound to the Organization, canonical case reference, and normalized
   sender mailbox. A plain or malformed `SUP-N` tag is acknowledged and ignored;
   RFC `From` plus an enumerable case number is never treated as write authority.
5. Stable provider-email idempotency keys make Resend retries replay-safe.

Other signed event types and messages for unconfigured recipients are
acknowledged and ignored. Dependency failures remain runtime failures so Web
Ingress returns a retryable server error instead of losing the email.

## Immutable configuration

```json
{
  "organization_id": "organization-1",
  "webhook_secret_reference": "support/resend-webhook",
  "api_key_secret_reference": "support/resend-api",
  "reply_token_secret_reference": "support/resend-reply-token",
  "recipient_addresses": ["support@example.com"],
  "max_webhook_age_seconds": 300
}
```

The bound Secrets provider must expose the Resend webhook signing secret
(`whsec_...`), API key, and an independent high-entropy reply-token secret of
at least 32 bytes. Outbound support mail generates reply tokens with
`issue_reply_token`; rotating this secret revokes every outstanding reply
address. The selected HTTP Client policy must allow exactly
`https://api.resend.com`.

## Required bindings

- `lenso.secrets@1`
- `lenso.http.client@1`
- `lenso.customer-directory@1`
- `lenso.support-intake@1`

The Support Case instance must allow the exact Resend Plugin instance key in
`intake_callers`; Customer Directory must allow the same key in its channel
caller list.

## Verification

Run from this repository:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

See [the Plugin card](docs/plugin-card.md) for ownership and removal behavior.
