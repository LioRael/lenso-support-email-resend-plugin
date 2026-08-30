//! Verified Resend inbound-email adapter for one Lenso Support App.

use std::collections::BTreeMap;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac as _};
use lenso::Port;
use lenso_capability_customer_directory as directory;
use lenso_capability_customer_directory::{
    CustomerDirectoryResolveOrCreateEmailContactInvocationError, ResolveOrCreateEmailContactRequest,
};
use lenso_capability_http_client as http_client;
use lenso_capability_http_client::{ClientInvocationError, SendRequest, SendRequestHeadersItem};
use lenso_capability_http_endpoint::{
    self as http_endpoint_contract, EndpointHandleInvocationError, HandleRequest, HandleResponse,
    endpoint,
    response::{self, StatusCode},
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_capability_support_intake as intake;
use lenso_capability_support_intake::{
    AppendChannelMessageRequest, GetRequesterCaseError, GetRequesterCaseRequest,
    OpenCaseFromChannelRequest, OpenCaseFromChannelRequestPriority,
    SupportIntakeAppendChannelMessageInvocationError, SupportIntakeGetRequesterCaseInvocationError,
    SupportIntakeOpenCaseFromChannelInvocationError,
};
use lenso_kernel::{InvocationContext, RuntimeFailure};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

const MAX_WEBHOOK_BYTES: usize = 256 * 1024;
const MAX_RETRIEVE_BYTES: usize = 2 * 1024 * 1024;
const MAX_REFERENCE_BYTES: usize = 512;
const MAX_ORGANIZATION_BYTES: usize = 512;
const MAX_RECIPIENTS: usize = 32;
const MAX_MESSAGE_BYTES: usize = 100_000;
const MAX_TITLE_BYTES: usize = 300;
const RESEND_API_ORIGIN: &str = "https://api.resend.com";

/// Forces this native Plugin crate to be retained by a linked Host.
pub const fn link() {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, lenso::PluginConfig)]
#[serde(deny_unknown_fields)]
pub struct ResendSupportEmailConfig {
    organization_id: String,
    webhook_secret_reference: String,
    api_key_secret_reference: String,
    reply_token_secret_reference: String,
    recipient_addresses: Vec<String>,
    max_webhook_age_seconds: i64,
}

impl ResendSupportEmailConfig {
    pub fn new(
        organization_id: impl Into<String>,
        webhook_secret_reference: impl Into<String>,
        api_key_secret_reference: impl Into<String>,
        reply_token_secret_reference: impl Into<String>,
        recipient_addresses: Vec<String>,
        max_webhook_age_seconds: i64,
    ) -> Result<Self, RuntimeFailure> {
        let config = Self {
            organization_id: organization_id.into(),
            webhook_secret_reference: webhook_secret_reference.into(),
            api_key_secret_reference: api_key_secret_reference.into(),
            reply_token_secret_reference: reply_token_secret_reference.into(),
            recipient_addresses,
            max_webhook_age_seconds,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), RuntimeFailure> {
        if !valid_opaque_identifier(&self.organization_id, MAX_ORGANIZATION_BYTES) {
            return Err(invalid_plan(
                "Resend Support Email organization_id is invalid",
            ));
        }
        if !valid_secret_reference(&self.webhook_secret_reference)
            || !valid_secret_reference(&self.api_key_secret_reference)
            || !valid_secret_reference(&self.reply_token_secret_reference)
            || self.webhook_secret_reference == self.api_key_secret_reference
            || self.webhook_secret_reference == self.reply_token_secret_reference
            || self.api_key_secret_reference == self.reply_token_secret_reference
        {
            return Err(invalid_plan(
                "Resend Support Email requires three distinct valid secret references",
            ));
        }
        if !(30..=900).contains(&self.max_webhook_age_seconds) {
            return Err(invalid_plan(
                "Resend Support Email webhook age must be between 30 and 900 seconds",
            ));
        }
        if self.recipient_addresses.is_empty() || self.recipient_addresses.len() > MAX_RECIPIENTS {
            return Err(invalid_plan(
                "Resend Support Email requires between 1 and 32 recipient addresses",
            ));
        }
        let mut normalized = self
            .recipient_addresses
            .iter()
            .map(|address| address.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if normalized
            .iter()
            .any(|address| address.contains('+') || !valid_email_address(address))
        {
            return Err(invalid_plan(
                "Resend Support Email recipient addresses must be plain valid mailboxes",
            ));
        }
        normalized.sort_unstable();
        if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid_plan(
                "Resend Support Email recipient addresses must be unique",
            ));
        }
        Ok(())
    }
}

fn validate_config(config: &ResendSupportEmailConfig) -> Result<(), RuntimeFailure> {
    config.validate()
}

#[lenso::plugin(validate = validate_config)]
#[derive(Clone, Debug)]
struct ResendSupportEmailPlugin {
    #[config]
    config: ResendSupportEmailConfig,
    secrets: Port<secrets::SecretsClient>,
    http: Port<http_client::ClientClient>,
    directory: Port<directory::CustomerDirectoryClient>,
    intake: Port<intake::SupportIntakeClient>,
}

#[endpoint]
impl ResendSupportEmailPlugin {
    #[post("support.email.resend.webhook", "/webhooks/resend")]
    #[openapi({
        summary: "Receive one verified Resend inbound-email event",
        responses: {
            "200": { description: "Event accepted, ignored, or idempotently replayed" },
            "400": { description: "Malformed webhook envelope" },
            "401": { description: "Missing, stale, or invalid Svix signature" },
            "503": { description: "A required Plugin or Resend is temporarily unavailable" }
        }
    })]
    async fn webhook(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if request.body.len() > MAX_WEBHOOK_BYTES {
            return Ok(problem_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "webhook_too_large",
                "The webhook body exceeds the accepted size.",
            ));
        }
        let Some(delivery_id) = header(&request, "svix-id") else {
            return Ok(signature_problem(
                "The webhook is missing its delivery identifier.",
            ));
        };
        let Some(timestamp) = header(&request, "svix-timestamp") else {
            return Ok(signature_problem(
                "The webhook is missing its signature timestamp.",
            ));
        };
        let Some(signature) = header(&request, "svix-signature") else {
            return Ok(signature_problem("The webhook is missing its signature."));
        };
        if !valid_delivery_id(delivery_id) {
            return Ok(signature_problem(
                "The webhook delivery identifier is invalid.",
            ));
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let Ok(signed_at) = timestamp.parse::<i64>() else {
            return Ok(signature_problem(
                "The webhook signature timestamp is invalid.",
            ));
        };
        if now.saturating_sub(signed_at).unsigned_abs()
            > self.config.max_webhook_age_seconds.unsigned_abs()
        {
            return Ok(signature_problem(
                "The webhook signature is outside the accepted time window.",
            ));
        }

        let webhook_secret = self
            .resolve_secret(context.clone(), &self.config.webhook_secret_reference)
            .await?;
        if !verify_svix_signature(
            &webhook_secret,
            delivery_id,
            timestamp,
            &request.body,
            signature,
        ) {
            return Ok(signature_problem("The webhook signature is invalid."));
        }

        let envelope: WebhookEnvelope = match serde_json::from_slice(&request.body) {
            Ok(envelope) => envelope,
            Err(_) => {
                return Ok(problem_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_webhook",
                    "The signed webhook body is not a supported JSON envelope.",
                ));
            }
        };
        if envelope.kind != "email.received" {
            return json_response(
                StatusCode::OK,
                &WebhookReceipt::ignored(delivery_id, &envelope.kind),
            );
        }
        if !valid_provider_id(&envelope.data.email_id) {
            return Ok(problem_response(
                StatusCode::BAD_REQUEST,
                "invalid_email_id",
                "The signed email event does not contain a valid email identifier.",
            ));
        }

        let api_key = self
            .resolve_secret(context.clone(), &self.config.api_key_secret_reference)
            .await?;
        let email = self
            .retrieve_email(context.clone(), &api_key, &envelope.data.email_id)
            .await?;
        if email.id != envelope.data.email_id {
            return Err(plugin_failure(
                "Resend returned an email that did not match the signed event",
            ));
        }
        match accepted_recipient_route(&email.to, &self.config.recipient_addresses) {
            RecipientRoute::NewCase => self.ingest_email(context, delivery_id, email, None).await,
            RecipientRoute::Thread(thread) => {
                self.ingest_email(context, delivery_id, email, Some(thread))
                    .await
            }
            RecipientRoute::InvalidThread => json_response(
                StatusCode::OK,
                &WebhookReceipt::ignored(delivery_id, "invalid_thread_recipient"),
            ),
            RecipientRoute::NotConfigured => json_response(
                StatusCode::OK,
                &WebhookReceipt::ignored(delivery_id, "recipient_not_configured"),
            ),
        }
    }
}

impl ResendSupportEmailPlugin {
    async fn resolve_secret(
        &self,
        context: InvocationContext,
        reference: &str,
    ) -> Result<String, EndpointHandleInvocationError> {
        self.secrets
            .resolve_with_context(
                context,
                ResolveRequest {
                    reference: reference.to_owned(),
                },
            )
            .await
            .map(|response| response.value)
            .map_err(|error| match error {
                SecretsInvocationError::Runtime(error) => {
                    EndpointHandleInvocationError::Runtime(error)
                }
                SecretsInvocationError::Domain(_) => {
                    plugin_failure("Resend Support Email could not resolve a configured secret")
                }
            })
    }

    async fn retrieve_email(
        &self,
        context: InvocationContext,
        api_key: &str,
        email_id: &str,
    ) -> Result<ReceivedEmail, EndpointHandleInvocationError> {
        let response = self
            .http
            .send_with_context(
                context,
                SendRequest {
                    body: Vec::new().into(),
                    headers: vec![
                        SendRequestHeadersItem {
                            name: "accept".to_owned(),
                            value: "application/json".to_owned(),
                        },
                        SendRequestHeadersItem {
                            name: "authorization".to_owned(),
                            value: format!("Bearer {api_key}"),
                        },
                    ],
                    method: "GET".to_owned(),
                    url: format!("{RESEND_API_ORIGIN}/emails/receiving/{email_id}"),
                },
            )
            .await
            .map_err(|error| match error {
                ClientInvocationError::Runtime(error) => {
                    EndpointHandleInvocationError::Runtime(error)
                }
                ClientInvocationError::Domain(_) => {
                    plugin_failure("Resend email retrieval is unavailable")
                }
            })?;
        if response.status != 200 {
            return Err(plugin_failure(
                "Resend did not return the requested inbound email",
            ));
        }
        if response.body.len() > MAX_RETRIEVE_BYTES {
            return Err(plugin_failure("Resend returned an oversized inbound email"));
        }
        serde_json::from_slice(&response.body)
            .map_err(|_| plugin_failure("Resend returned an invalid inbound email response"))
    }

    async fn ingest_email(
        &self,
        context: InvocationContext,
        delivery_id: &str,
        email: ReceivedEmail,
        requested_thread: Option<ThreadRecipient>,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let Some((display_name, sender_email)) = parse_mailbox(&email.from) else {
            return json_response(
                StatusCode::OK,
                &WebhookReceipt::ignored(delivery_id, "invalid_sender"),
            );
        };
        if let Some(thread) = requested_thread.as_ref() {
            let reply_token_secret = self
                .resolve_secret(context.clone(), &self.config.reply_token_secret_reference)
                .await?;
            if !(32..=4096).contains(&reply_token_secret.len()) {
                return Err(plugin_failure(
                    "Resend Support Email reply token secret must contain 32 to 4096 bytes",
                ));
            }
            if !verify_reply_token(
                &reply_token_secret,
                &self.config.organization_id,
                &thread.case_ref,
                &sender_email,
                &thread.token,
            ) {
                return json_response(
                    StatusCode::OK,
                    &WebhookReceipt::ignored(delivery_id, "invalid_reply_token"),
                );
            }
        }
        let provider_key = provider_key(&email.id);
        let contact = self
            .directory
            .resolve_or_create_email_contact_with_context(
                context.clone(),
                ResolveOrCreateEmailContactRequest {
                    display_name,
                    email: sender_email,
                    idempotency_key: format!("{provider_key}:contact"),
                    organization_id: self.config.organization_id.clone(),
                },
            )
            .await
            .map_err(|error| match error {
                CustomerDirectoryResolveOrCreateEmailContactInvocationError::Runtime(error) => {
                    EndpointHandleInvocationError::Runtime(error)
                }
                CustomerDirectoryResolveOrCreateEmailContactInvocationError::Domain(_) => {
                    plugin_failure("Customer Directory rejected an inbound email contact")
                }
            })?
            .contact;
        let requester_subject = format!("customer:{}", contact.canonical_contact_id);
        let body = bounded_message(email.text.as_deref(), email.html.as_deref());

        if let Some(thread) = requested_thread {
            match self
                .intake
                .get_requester_case_with_context(
                    context.clone(),
                    GetRequesterCaseRequest {
                        case_ref: thread.case_ref,
                        organization_id: self.config.organization_id.clone(),
                        requester_subject: requester_subject.clone(),
                    },
                )
                .await
            {
                Ok(case) => {
                    let appended = self
                        .intake
                        .append_channel_message_with_context(
                            context,
                            AppendChannelMessageRequest {
                                body,
                                case_ref: case.case_id.clone(),
                                expected_revision: case.revision,
                                idempotency_key: format!("{provider_key}:message"),
                                organization_id: self.config.organization_id.clone(),
                                requester_subject,
                            },
                        )
                        .await
                        .map_err(map_append_error)?;
                    return json_response(
                        StatusCode::OK,
                        &WebhookReceipt::appended(
                            delivery_id,
                            &email.id,
                            &appended.case_id,
                            &appended.message_id,
                        ),
                    );
                }
                Err(SupportIntakeGetRequesterCaseInvocationError::Domain(
                    GetRequesterCaseError::CaseNotFound,
                )) => {}
                Err(SupportIntakeGetRequesterCaseInvocationError::Runtime(error)) => {
                    return Err(EndpointHandleInvocationError::Runtime(error));
                }
                Err(SupportIntakeGetRequesterCaseInvocationError::Domain(_)) => {
                    return Err(plugin_failure(
                        "Support Intake rejected an inbound email thread lookup",
                    ));
                }
            }
        }

        let opened = self
            .intake
            .open_case_from_channel_with_context(
                context,
                OpenCaseFromChannelRequest {
                    description: body,
                    idempotency_key: format!("{provider_key}:case"),
                    organization_id: self.config.organization_id.clone(),
                    priority: OpenCaseFromChannelRequestPriority::Normal,
                    requester_subject,
                    title: bounded_title(&email.subject),
                },
            )
            .await
            .map_err(map_open_error)?;
        json_response(
            StatusCode::OK,
            &WebhookReceipt::opened(delivery_id, &email.id, &opened.case_id, &opened.identifier),
        )
    }
}

#[derive(Debug, Deserialize)]
struct WebhookEnvelope {
    #[serde(rename = "type")]
    kind: String,
    data: WebhookReceivedData,
}

#[derive(Debug, Deserialize)]
struct WebhookReceivedData {
    email_id: String,
}

#[derive(Debug, Deserialize)]
struct ReceivedEmail {
    id: String,
    from: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct WebhookReceipt<'a> {
    delivery_id: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<&'a str>,
}

impl<'a> WebhookReceipt<'a> {
    const fn ignored(delivery_id: &'a str, reason: &'a str) -> Self {
        Self {
            delivery_id,
            outcome: reason,
            email_id: None,
            case_id: None,
            case_ref: None,
            message_id: None,
        }
    }

    const fn opened(
        delivery_id: &'a str,
        email_id: &'a str,
        case_id: &'a str,
        case_ref: &'a str,
    ) -> Self {
        Self {
            delivery_id,
            outcome: "case_opened",
            email_id: Some(email_id),
            case_id: Some(case_id),
            case_ref: Some(case_ref),
            message_id: None,
        }
    }

    const fn appended(
        delivery_id: &'a str,
        email_id: &'a str,
        case_id: &'a str,
        message_id: &'a str,
    ) -> Self {
        Self {
            delivery_id,
            outcome: "message_appended",
            email_id: Some(email_id),
            case_id: Some(case_id),
            case_ref: None,
            message_id: Some(message_id),
        }
    }
}

fn map_open_error(
    error: SupportIntakeOpenCaseFromChannelInvocationError,
) -> EndpointHandleInvocationError {
    match error {
        SupportIntakeOpenCaseFromChannelInvocationError::Runtime(error) => {
            EndpointHandleInvocationError::Runtime(error)
        }
        SupportIntakeOpenCaseFromChannelInvocationError::Domain(_) => {
            plugin_failure("Support Intake rejected an inbound email case")
        }
    }
}

fn map_append_error(
    error: SupportIntakeAppendChannelMessageInvocationError,
) -> EndpointHandleInvocationError {
    match error {
        SupportIntakeAppendChannelMessageInvocationError::Runtime(error) => {
            EndpointHandleInvocationError::Runtime(error)
        }
        SupportIntakeAppendChannelMessageInvocationError::Domain(_) => {
            plugin_failure("Support Intake rejected an inbound email message")
        }
    }
}

fn header<'a>(request: &'a HandleRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn verify_svix_signature(
    secret: &str,
    delivery_id: &str,
    timestamp: &str,
    body: &[u8],
    signatures: &str,
) -> bool {
    let Some(secret) = decode_webhook_secret(secret) else {
        return false;
    };
    let mut signed = Vec::with_capacity(delivery_id.len() + timestamp.len() + body.len() + 2);
    signed.extend_from_slice(delivery_id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(body);

    signatures.split_ascii_whitespace().any(|candidate| {
        let Some(encoded) = candidate.strip_prefix("v1,") else {
            return false;
        };
        let Ok(signature) = STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(mut verifier) = HmacSha256::new_from_slice(&secret) else {
            return false;
        };
        verifier.update(&signed);
        verifier.verify_slice(&signature).is_ok()
    })
}

fn decode_webhook_secret(secret: &str) -> Option<Vec<u8>> {
    let encoded = secret.strip_prefix("whsec_")?;
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .ok()
        .filter(|bytes| !bytes.is_empty())
}

#[derive(Clone, Eq, PartialEq)]
struct ThreadRecipient {
    case_ref: String,
    token: String,
}

enum RecipientRoute {
    NewCase,
    Thread(ThreadRecipient),
    InvalidThread,
    NotConfigured,
}

fn accepted_recipient_route(recipients: &[String], accepted: &[String]) -> RecipientRoute {
    let mut selected = None;
    for recipient in recipients {
        let Some((_, address)) = parse_mailbox_preserving_address_case(recipient) else {
            continue;
        };
        let Some((local, domain)) = address.split_once('@') else {
            continue;
        };
        let (base_local, tag) = local
            .split_once('+')
            .map_or((local, None), |(base, tag)| (base, Some(tag)));
        let base = format!("{base_local}@{domain}");
        if !accepted
            .iter()
            .any(|accepted| accepted.eq_ignore_ascii_case(&base))
        {
            continue;
        }
        let route = match tag {
            None => RecipientRoute::NewCase,
            Some(tag) => match parse_thread_recipient(tag) {
                Some(thread) => RecipientRoute::Thread(thread),
                None => return RecipientRoute::InvalidThread,
            },
        };
        if selected.is_some() {
            return RecipientRoute::InvalidThread;
        }
        selected = Some(route);
    }
    selected.unwrap_or(RecipientRoute::NotConfigured)
}

fn parse_thread_recipient(tag: &str) -> Option<ThreadRecipient> {
    let (case_ref, token) = tag.rsplit_once('.')?;
    let case_ref = canonical_support_case_ref(case_ref)?;
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    (decoded.len() == 32).then(|| ThreadRecipient {
        case_ref,
        token: token.to_owned(),
    })
}

/// Issues the bearer token used in a `support+SUP-N.<token>@domain` reply address.
///
/// The caller must use the exact configured Organization, canonical `SUP-N`
/// reference, and normalized lowercase sender mailbox that the receiving path
/// will verify. Rotating the secret revokes all previously issued reply tokens.
pub fn issue_reply_token(
    secret: &str,
    organization_id: &str,
    case_ref: &str,
    sender_email: &str,
) -> Option<String> {
    if !valid_opaque_identifier(organization_id, MAX_ORGANIZATION_BYTES)
        || canonical_support_case_ref(case_ref).as_deref() != Some(case_ref)
        || !valid_email_address(sender_email)
        || sender_email != sender_email.to_ascii_lowercase()
    {
        return None;
    }
    let mac = reply_token_mac(secret, organization_id, case_ref, sender_email)?;
    Some(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_reply_token(
    secret: &str,
    organization_id: &str,
    case_ref: &str,
    sender_email: &str,
    token: &str,
) -> bool {
    let Ok(token) = URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let Some(mac) = reply_token_mac(secret, organization_id, case_ref, sender_email) else {
        return false;
    };
    mac.verify_slice(&token).is_ok()
}

fn reply_token_mac(
    secret: &str,
    organization_id: &str,
    case_ref: &str,
    sender_email: &str,
) -> Option<HmacSha256> {
    if !(32..=4096).contains(&secret.len()) {
        return None;
    }
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(b"lenso.support-email.resend.reply-token.v1\0");
    mac.update(organization_id.as_bytes());
    mac.update(b"\0");
    mac.update(case_ref.as_bytes());
    mac.update(b"\0");
    mac.update(sender_email.as_bytes());
    Some(mac)
}

fn parse_mailbox(value: &str) -> Option<(Option<String>, String)> {
    parse_mailbox_preserving_address_case(value)
        .map(|(display_name, address)| (display_name, address.to_ascii_lowercase()))
}

fn parse_mailbox_preserving_address_case(value: &str) -> Option<(Option<String>, String)> {
    let trimmed = value.trim();
    let (display_name, address) = if let Some(start) = trimmed.rfind('<') {
        let end = trimmed.rfind('>')?;
        if end <= start || !trimmed[end + 1..].trim().is_empty() {
            return None;
        }
        let display = trimmed[..start].trim().trim_matches('"').trim();
        (
            (!display.is_empty()).then(|| bounded_display_name(display)),
            trimmed[start + 1..end].trim(),
        )
    } else {
        (None, trimmed)
    };
    valid_email_address(address).then_some((display_name, address.to_owned()))
}

fn valid_email_address(value: &str) -> bool {
    if value.is_empty() || value.len() > 320 || !value.is_ascii() {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-' | b'@')
        })
}

fn bounded_display_name(value: &str) -> String {
    truncate_utf8(value.trim(), 200).to_owned()
}

fn bounded_title(subject: &str) -> String {
    let subject = subject.trim();
    if subject.is_empty() {
        return "Email support request".to_owned();
    }
    truncate_utf8(subject, MAX_TITLE_BYTES).to_owned()
}

fn bounded_message(text: Option<&str>, html: Option<&str>) -> String {
    let candidate = text
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            html.map(html_to_text)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "(empty email)".to_owned());
    truncate_utf8(&candidate, MAX_MESSAGE_BYTES).to_owned()
}

fn html_to_text(html: &str) -> String {
    let mut output = String::with_capacity(html.len().min(MAX_MESSAGE_BYTES));
    let mut in_tag = false;
    let mut previous_space = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                if !previous_space && !output.is_empty() {
                    output.push(' ');
                    previous_space = true;
                }
            }
            _ if in_tag => {}
            _ if character.is_whitespace() => {
                if !previous_space && !output.is_empty() {
                    output.push(' ');
                    previous_space = true;
                }
            }
            _ => {
                output.push(character);
                previous_space = false;
            }
        }
        if output.len() >= MAX_MESSAGE_BYTES {
            break;
        }
    }
    output
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .trim()
        .to_owned()
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn canonical_support_case_ref(value: &str) -> Option<String> {
    let (prefix, number) = value.split_at_checked(4)?;
    (prefix.eq_ignore_ascii_case("SUP-")
        && !number.is_empty()
        && !number.starts_with('0')
        && number.bytes().all(|byte| byte.is_ascii_digit()))
    .then(|| format!("SUP-{number}"))
}

fn provider_key(email_id: &str) -> String {
    format!("resend:{email_id}")
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_delivery_id(value: &str) -> bool {
    valid_provider_id(value)
}

fn valid_secret_reference(value: &str) -> bool {
    valid_opaque_identifier(value, MAX_REFERENCE_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-'))
}

fn valid_opaque_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn json_response(
    status: StatusCode,
    value: &impl Serialize,
) -> Result<HandleResponse, EndpointHandleInvocationError> {
    response::json(status, value).map_err(Into::into)
}

fn signature_problem(detail: &str) -> HandleResponse {
    problem_response(
        StatusCode::UNAUTHORIZED,
        "invalid_webhook_signature",
        detail,
    )
}

fn problem_response(status: StatusCode, code: &str, detail: &str) -> HandleResponse {
    response::problem(status, code, detail)
}

fn plugin_failure(detail: &str) -> EndpointHandleInvocationError {
    EndpointHandleInvocationError::Runtime(RuntimeFailure::PluginFailure {
        detail: detail.to_owned(),
    })
}

fn invalid_plan(detail: &str) -> RuntimeFailure {
    RuntimeFailure::InvalidResolvedPlan {
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use futures::executor::block_on;
    use lenso_capability_http_endpoint::testing::EndpointTest;

    use super::*;

    fn config() -> ResendSupportEmailConfig {
        ResendSupportEmailConfig::new(
            "organization-1",
            "support/resend-webhook",
            "support/resend-api",
            "support/resend-reply-token",
            vec!["support@example.com".to_owned()],
            300,
        )
        .unwrap()
    }

    fn plugin() -> ResendSupportEmailPlugin {
        ResendSupportEmailPlugin {
            config: config(),
            secrets: Port::default(),
            http: Port::default(),
            directory: Port::default(),
            intake: Port::default(),
        }
    }

    #[test]
    fn verifies_raw_body_against_svix_v1_signature() {
        let key = b"webhook-test-key";
        let secret = format!("whsec_{}", STANDARD.encode(key));
        let body = br#"{"type":"email.received"}"#;
        let delivery_id = "msg_123";
        let timestamp = "1700000000";
        let signed = [
            delivery_id.as_bytes(),
            b".",
            timestamp.as_bytes(),
            b".",
            body,
        ]
        .concat();
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(&signed);
        let signature = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));

        assert!(verify_svix_signature(
            &secret,
            delivery_id,
            timestamp,
            body,
            &signature
        ));
        assert!(!verify_svix_signature(
            &secret,
            delivery_id,
            timestamp,
            b"changed",
            &signature
        ));
    }

    #[test]
    fn parses_display_mailboxes_and_requires_an_unforgeable_thread_token() {
        assert_eq!(
            parse_mailbox("Ada Lovelace <ADA@example.com>"),
            Some((
                Some("Ada Lovelace".to_owned()),
                "ada@example.com".to_owned()
            ))
        );
        let secret = "a-strong-reply-token-secret-with-32-bytes";
        let token =
            issue_reply_token(secret, "organization-1", "SUP-42", "ada@example.com").unwrap();
        let route = accepted_recipient_route(
            &[format!("Support <support+SUP-42.{token}@example.com>")],
            &["support@example.com".to_owned()],
        );
        let RecipientRoute::Thread(thread) = route else {
            panic!("expected an authenticated thread route");
        };
        assert_eq!(thread.case_ref, "SUP-42");
        assert!(verify_reply_token(
            secret,
            "organization-1",
            &thread.case_ref,
            "ada@example.com",
            &thread.token,
        ));
        assert!(!verify_reply_token(
            secret,
            "organization-1",
            &thread.case_ref,
            "victim@example.com",
            &thread.token,
        ));
        assert!(matches!(
            accepted_recipient_route(
                &["Support <support+SUP-42@example.com>".to_owned()],
                &["support@example.com".to_owned()]
            ),
            RecipientRoute::InvalidThread
        ));
        assert_eq!(
            canonical_support_case_ref("sup-7"),
            Some("SUP-7".to_owned())
        );
        assert_eq!(canonical_support_case_ref("ticket-7"), None);
        assert_eq!(canonical_support_case_ref("SUP-0"), None);
    }

    #[test]
    fn prefers_plain_text_and_bounds_html_fallback() {
        assert_eq!(
            bounded_message(Some("  plain reply  "), Some("<p>ignored</p>")),
            "plain reply"
        );
        assert_eq!(
            bounded_message(None, Some("<p>Hello <b>world</b></p>")),
            "Hello world"
        );
    }

    #[test]
    fn rejects_invalid_configuration_without_exposing_secrets() {
        assert!(
            ResendSupportEmailConfig::new(
                "organization-1",
                "same-secret",
                "same-secret",
                "reply-secret",
                vec!["support@example.com".to_owned()],
                300,
            )
            .is_err()
        );
        assert!(
            ResendSupportEmailConfig::new(
                "organization-1",
                "webhook-secret",
                "api-secret",
                "reply-secret",
                vec!["support+case@example.com".to_owned()],
                300,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unsigned_requests_before_touching_required_ports() {
        let response = block_on(async {
            EndpointTest::new(plugin())
                .request("support.email.resend.webhook")
                .json(
                    &serde_json::json!({"type": "email.received", "data": {"email_id": "email_1"}}),
                )
                .unwrap()
                .send()
                .await
                .unwrap()
        });
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.header("content-type"),
            Some("application/problem+json; charset=utf-8")
        );
    }

    #[test]
    fn descriptor_declares_only_the_channel_boundary_and_required_ports() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.http.endpoint@1"
        );
        let mut required = descriptor["required_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["capability_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        required.sort_unstable();
        assert_eq!(
            required,
            vec![
                "lenso.customer-directory@1",
                "lenso.http.client@1",
                "lenso.secrets@1",
                "lenso.support-intake@1",
            ]
        );
    }
}
