# Resend Support Email Plugin card

## Job

Let a customer email the configured support address and reliably create or
continue their support case.

## Owns

- Resend/Svix webhook verification policy.
- Resend API retrieval and response validation.
- Email mailbox normalization and configured-recipient routing.
- HMAC reply-address tokens bound to Organization, case, and normalized sender.
- The deterministic mapping from provider email IDs to downstream idempotency
  keys.

## Does not own

- Customer identity or contact merging (`lenso.customer-directory@1`).
- Case, message, revision, or visibility facts (`lenso.support-intake@1`).
- Secret values (`lenso.secrets@1`).
- Network policy or transport (`lenso.http.client@1`).
- Binary attachment persistence (`lenso.support-attachment@1`).

## Security boundary

The Plugin verifies the raw body before JSON parsing or any customer/case
mutation. Signature timestamps are bounded, secrets are referenced rather than
stored in Plugin configuration, and recipients are exact allowlisted mailboxes.
Thread continuation requires a full HMAC-SHA256 bearer token before contact
resolution or case lookup, then Support Intake re-authorizes the resolved
requester. A webhook signature authenticates Resend delivery, not ownership of
the message's RFC `From`; therefore `From + SUP-N` is never sufficient.

## Retry behavior

Resend may redeliver the same event. Contact resolution, case opening, and
message append use stable keys derived from `email_id`. Support Intake treats an
optimistic revision as a first-attempt guard rather than part of the semantic
receipt hash, so a retried append can replay after re-reading the current case.

## Removal

Removing this Plugin removes the Resend route and stops future email ingestion.
It does not delete contacts, cases, or messages already accepted by their owning
Plugins. Reinstalling with the same dependencies can safely replay a retained
Resend event.

## Deliberate prerequisite

Messages with binary attachments need a separate ingestion path that creates a
Content Vault object and then calls `lenso.support-attachment@1`. This adapter
does not silently claim or discard attachment bytes.
