use std::{sync::LazyLock, time::Duration};

use chrono::Utc;
use data_encoding::BASE64;
use derive_more::{AsRef, Deref, Display, From, Into};
use openssl::{pkey::PKey, rsa::Padding};
use regex::Regex;
use url::Url;

use crate::{
    CONFIG,
    api::ApiResult,
    api::core::{accept_org_invite, log_event},
    auth,
    auth::{AuthMethod, AuthTokens, BW_EXPIRATION, ClientIp, DEFAULT_REFRESH_VALIDITY, TokenWrapper},
    db::{
        DbConn,
        models::{
            Collection, Device, EventType, Membership, MembershipStatus, MembershipType, OIDCAuthenticatedUser,
            OrgPolicy, Organization, OrganizationId, SsoAuth, SsoUser, User,
        },
    },
    mail,
    sso_client::Client,
};

pub static FAKE_SSO_IDENTIFIER: &str = "00000000-01DC-01DC-01DC-000000000000";

static SSO_JWT_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|sso", CONFIG.domain_origin()));

pub static SSO_AUTH_EXPIRATION: LazyLock<chrono::Duration> =
    LazyLock::new(|| chrono::TimeDelta::try_minutes(10).unwrap());

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCCode(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeChallenge(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeVerifier(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCState(String);

#[derive(Debug, Serialize, Deserialize)]
struct SsoTokenJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn encode_ssotoken_claims() -> String {
    let time_now = Utc::now();
    let claims = SsoTokenJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + chrono::TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        sub: "vaultwarden".to_owned(),
    };

    auth::encode_jwt(&claims)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenClaims {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

#[derive(Deserialize)]
struct BasicTokenClaimsValidation {
    exp: u64,
    iss: String,
}

impl BasicTokenClaims {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().timestamp())
    }
}

fn decode_token_claims(token_name: &str, token: &str) -> ApiResult<BasicTokenClaims> {
    // We need to manually validate this token, since `insecure_decode` does not do this
    match jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaimsValidation>(token) {
        Ok(btcv) => {
            let now = jsonwebtoken::get_current_timestamp();
            let validate_claim = btcv.claims;
            // Validate the exp in the claim with a leeway of 60 seconds, same as jsonwebtoken does
            if validate_claim.exp < now - 60 {
                err_silent!(format!("Expired Signature for base token claim from {token_name}"))
            }
            if validate_claim.iss.ne(&CONFIG.sso_authority()) {
                err_silent!(format!("Invalid Issuer for base token claim from {token_name}"))
            }

            // All is validated and ok, lets decode again using the wanted struct
            let btc = jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaims>(token).unwrap();
            Ok(btc.claims)
        }
        Err(err) => err_silent!(format!("Failed to decode basic token claims from {token_name}: {err}")),
    }
}

pub fn decode_state(base64_state: &str) -> ApiResult<OIDCState> {
    let state = if let Ok(vec) = BASE64.decode(base64_state.as_bytes()) {
        if let Ok(valid) = String::from_utf8(vec) {
            OIDCState(valid)
        } else {
            err!(format!("Invalid utf8 chars in {base64_state} after base64 decoding"))
        }
    } else {
        err!(format!("Failed to decode {base64_state} using base64"))
    };

    Ok(state)
}

// redirect_uri from: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/ApiClient.cs
pub async fn authorize_url(
    state: OIDCState,
    client_challenge: OIDCCodeChallenge,
    client_id: &str,
    raw_redirect_uri: &str,
    binding_hash: Option<String>,
    conn: DbConn,
) -> ApiResult<Url> {
    let redirect_uri = match client_id {
        "web" | "browser" => format!("{}/sso-connector.html", CONFIG.domain()),
        "desktop" | "mobile" => "bitwarden://sso-callback".to_owned(),
        "cli" => {
            let port_regex = Regex::new(r"^http://localhost:([0-9]{4})$").unwrap();
            if let Some(port) =
                port_regex.captures(raw_redirect_uri).and_then(|captures| captures.get(1).map(|c| c.as_str()))
            {
                format!("http://localhost:{port}")
            } else {
                err!("Failed to extract port number")
            }
        }
        _ => err!(format!("Unsupported client {client_id}")),
    };

    let (auth_url, sso_auth) = Client::authorize_url(state, client_challenge, redirect_uri, binding_hash).await?;
    sso_auth.save(&conn).await?;
    Ok(auth_url)
}

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCIdentifier(String);

impl OIDCIdentifier {
    fn new(issuer: &str, subject: &str) -> Self {
        OIDCIdentifier(format!("{issuer}/{subject}"))
    }
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on `SsoAuth.auth_response` since the `code` has already been exchanged.
// The `SsoAuth` will ensure that the user is authorized only once.
pub async fn exchange_code(
    code: &OIDCCode,
    client_verifier: OIDCCodeVerifier,
    conn: &DbConn,
) -> ApiResult<(SsoAuth, OIDCAuthenticatedUser)> {
    use openidconnect::OAuth2TokenResponse;

    let Some(mut sso_auth) = SsoAuth::find_by_code(code, conn).await else {
        err!("Invalid code cannot retrieve sso auth")
    };

    if let Some(authenticated_user) = sso_auth.auth_response.clone() {
        return Ok((sso_auth, authenticated_user));
    }

    let code = match (sso_auth.code_response.clone(), sso_auth.code_response_error.as_ref()) {
        (Some(code), None) => code,
        (_, Some(re)) => {
            let error_msg = format!(
                "SSO authorization failed: {}, {}",
                re.error,
                re.error_description.as_ref().unwrap_or(&String::new())
            );
            sso_auth.delete(conn).await?;
            err!(error_msg);
        }
        (None, _) => {
            sso_auth.delete(conn).await?;
            err!("Missing authorization provider return");
        }
    };

    let client = Client::cached().await?;
    let (token_response, id_claims) = client.exchange_code(code, client_verifier, &sso_auth).await?;

    let user_info = client.user_info(token_response.access_token().to_owned()).await?;

    let email = match id_claims.email().or(user_info.email()) {
        None => err!("Neither id token nor userinfo contained an email"),
        Some(e) => e.to_string().to_lowercase(),
    };

    let email_verified = id_claims.email_verified().or(user_info.email_verified());

    let user_name = id_claims.preferred_username().or(user_info.preferred_username()).map(|un| un.to_string());

    let refresh_token = token_response.refresh_token().map(openidconnect::RefreshToken::secret);
    if refresh_token.is_none() && CONFIG.sso_scopes_vec().contains(&"offline_access".to_owned()) {
        error!("Scope offline_access is present but response contain no refresh_token");
    }

    let identifier = OIDCIdentifier::new(id_claims.issuer(), id_claims.subject());

    let authenticated_user = OIDCAuthenticatedUser {
        refresh_token: refresh_token.cloned(),
        access_token: token_response.access_token().secret().clone(),
        expires_in: token_response.expires_in(),
        identifier: identifier.clone(),
        email: email.clone(),
        email_verified,
        user_name: user_name.clone(),
    };

    debug!("Authenticated user {authenticated_user:?}");
    sso_auth.auth_response = Some(authenticated_user.clone());
    sso_auth.updated_at = Utc::now().naive_utc();
    sso_auth.save(conn).await?;

    Ok((sso_auth, authenticated_user))
}

fn encrypt_org_key_for_user(org_key: &[u8], user_public_key: &str) -> ApiResult<String> {
    let public_key_der = match BASE64.decode(user_public_key.as_bytes()) {
        Ok(public_key_der) => public_key_der,
        Err(err) => err!(format!("Failed to decode SSO auto-confirm user public key: {err}")),
    };

    let public_key = match PKey::public_key_from_der(&public_key_der) {
        Ok(public_key) => public_key,
        Err(err) => err!(format!("Failed to parse SSO auto-confirm user public key: {err}")),
    };

    let rsa = match public_key.rsa() {
        Ok(rsa) => rsa,
        Err(err) => err!(format!("SSO auto-confirm user public key is not RSA: {err}")),
    };

    let mut encrypted_key = vec![0; rsa.size() as usize];
    let encrypted_len = match rsa.public_encrypt(org_key, &mut encrypted_key, Padding::PKCS1_OAEP) {
        Ok(encrypted_len) => encrypted_len,
        Err(err) => err!(format!("Failed to encrypt SSO auto-confirm org key: {err}")),
    };
    encrypted_key.truncate(encrypted_len);

    Ok(format!("4.{}", BASE64.encode(&encrypted_key)))
}

pub(crate) fn is_reserved_sso_org_bot_email(email: &str) -> bool {
    CONFIG.sso_org_bootstrap() && email.eq_ignore_ascii_case(&CONFIG.sso_org_bot_email())
}

async fn auto_confirm_default_org_membership(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    org: &Organization,
    mut member: Membership,
    conn: &DbConn,
) -> ApiResult<()> {
    if !CONFIG.sso_org_auto_confirm() || member.status != MembershipStatus::Accepted as i32 {
        return Ok(());
    }

    let Some(org_key_b64) = CONFIG.sso_org_auto_confirm_key() else {
        err!("SSO_ORG_AUTO_CONFIRM_KEY must be configured when SSO_ORG_AUTO_CONFIRM is enabled")
    };

    let Some(user_public_key) = user.public_key.as_deref() else {
        err!(format!("SSO auto-confirm requires a public key for {}", user.email))
    };

    let org_key = match BASE64.decode(org_key_b64.as_bytes()) {
        Ok(org_key) => org_key,
        Err(err) => err!(format!("Failed to decode SSO_ORG_AUTO_CONFIRM_KEY: {err}")),
    };

    member.akey = encrypt_org_key_for_user(&org_key, user_public_key)?;
    member.status = MembershipStatus::Confirmed as i32;

    OrgPolicy::check_user_allowed(&member, "confirm", conn).await?;

    log_event(
        EventType::OrganizationUserConfirmed as i32,
        &member.uuid,
        &org.uuid,
        &user.uuid,
        device.atype,
        &ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled()
        && let Err(err) = mail::send_invite_confirmed(&user.email, &org.name).await
    {
        error!("Failed to send SSO default org confirmation mail to {}: {err}", user.email);
    }

    member.save(conn).await?;
    Ok(())
}

async fn ensure_sso_org_bot_membership(org: &Organization, conn: &DbConn) -> ApiResult<()> {
    if !CONFIG.sso_org_bootstrap() {
        return Ok(());
    }

    let bot_email = CONFIG.sso_org_bot_email().to_lowercase();
    let bot = if let Some(bot) = User::find_by_mail(&bot_email, conn).await {
        if matches!(SsoUser::find_by_mail(&bot_email, conn).await, Some((_, Some(_))))
            || bot.private_key.is_some()
            || bot.name != "SSO Organization Bot"
        {
            err!(format!("SSO_ORG_BOT_EMAIL {bot_email} is already used by an interactive or SSO-linked account"));
        }
        bot
    } else {
        let mut bot = User::new(&bot_email, Some("SSO Organization Bot".to_owned()));
        bot.verified_at = Some(Utc::now().naive_utc());
        bot.save(conn).await?;
        bot
    };

    if let Some(mut member) = Membership::find_by_user_and_org(&bot.uuid, &org.uuid, conn).await {
        let changed = if member.atype == MembershipType::Owner as i32 {
            false
        } else {
            member.atype = MembershipType::Owner as i32;
            true
        };
        let changed = if member.status == MembershipStatus::Confirmed as i32 {
            changed
        } else {
            member.status = MembershipStatus::Confirmed as i32;
            true
        };
        let changed = if member.access_all {
            changed
        } else {
            member.access_all = true;
            true
        };
        if changed {
            member.save(conn).await?;
        }
    } else {
        let mut member = Membership::new(bot.uuid, org.uuid.clone(), None);
        member.access_all = true;
        member.atype = MembershipType::Owner as i32;
        member.status = MembershipStatus::Confirmed as i32;
        member.save(conn).await?;
    }

    Ok(())
}

async fn ensure_sso_org_bootstrap_collection(org: &Organization, conn: &DbConn) -> ApiResult<()> {
    let collection_name = CONFIG.sso_org_bootstrap_collection_name();
    if Collection::find_by_organization(&org.uuid, conn)
        .await
        .iter()
        .any(|collection| collection.name == collection_name)
    {
        return Ok(());
    }

    let collection = Collection::new(org.uuid.clone(), collection_name, None);
    collection.save(conn).await
}

async fn bootstrap_default_sso_org(org_id: OrganizationId, conn: &DbConn) -> ApiResult<Organization> {
    let Some(org_name) = CONFIG.sso_org_bootstrap_name() else {
        err!("SSO_ORG_BOOTSTRAP_NAME must be configured when SSO_ORG_BOOTSTRAP is enabled")
    };
    let Some(billing_email) = CONFIG.sso_org_bootstrap_billing_email() else {
        err!("SSO_ORG_BOOTSTRAP_BILLING_EMAIL must be configured when SSO_ORG_BOOTSTRAP is enabled")
    };

    let mut org = Organization::new(org_name, &billing_email, None, None);
    org.uuid = org_id;
    org.save(conn).await?;

    ensure_sso_org_bootstrap_collection(&org, conn).await?;
    ensure_sso_org_bot_membership(&org, conn).await?;
    Ok(org)
}

async fn resolve_default_sso_org(conn: &DbConn) -> ApiResult<Organization> {
    let configured_org_id = CONFIG.sso_default_org_id().map(OrganizationId::from);

    if let Some(org_id) = configured_org_id.clone() {
        if let Some(org) = Organization::find_by_uuid(&org_id, conn).await {
            ensure_sso_org_bot_membership(&org, conn).await?;
            return Ok(org);
        }

        if !CONFIG.sso_org_bootstrap() {
            err!(format!("Configured SSO default organization {org_id} does not exist"));
        }

        return bootstrap_default_sso_org(org_id, conn).await;
    }

    err!("SSO_DEFAULT_ORG_ID must be configured when SSO organization provisioning is enabled")
}

pub(crate) async fn reconcile_default_org_membership(
    user: &User,
    device: &Device,
    ip: &ClientIp,
    conn: &DbConn,
) -> ApiResult<()> {
    if !CONFIG.sso_org_auto_provision() && !CONFIG.sso_org_invite_auto_accept() {
        return Ok(());
    }

    let org = resolve_default_sso_org(conn).await?;

    if let Some(member) = Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await {
        match member.status {
            x if x == MembershipStatus::Confirmed as i32 => Ok(()),
            x if x == MembershipStatus::Accepted as i32 => {
                auto_confirm_default_org_membership(user, device, ip, &org, member, conn).await
            }
            x if x == MembershipStatus::Invited as i32 => {
                if !CONFIG.sso_org_invite_auto_accept() {
                    return Ok(());
                }

                accept_org_invite(user, member, None, conn).await?;

                if let Some(updated_member) = Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await
                    && let Err(err) =
                        auto_confirm_default_org_membership(user, device, ip, &org, updated_member, conn).await
                {
                    error!("Failed to auto-confirm default SSO organization membership for {}: {err}", user.email);
                }

                if CONFIG.mail_enabled()
                    && !CONFIG.sso_org_auto_confirm()
                    && let Err(err) = mail::send_enrolled(&user.email, &org.name).await
                {
                    error!("Failed to send SSO default org enrollment mail to {}: {err}", user.email);
                }

                Ok(())
            }
            _ => Ok(()),
        }
    } else {
        if !CONFIG.sso_org_auto_provision() {
            return Ok(());
        }

        let mut member = Membership::new(user.uuid.clone(), org.uuid.clone(), Some(org.billing_email.clone()));
        member.access_all = false;
        member.atype = MembershipType::User as i32;

        if CONFIG.sso_org_invite_auto_accept() {
            member.status = MembershipStatus::Accepted as i32;
        } else {
            member.status = MembershipStatus::Invited as i32;
        }
        OrgPolicy::check_user_allowed(&member, "join", conn).await?;

        if let Err(err) = member.save(conn).await {
            if Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await.is_some() {
                return Ok(());
            }
            return Err(err);
        }

        log_event(
            EventType::OrganizationUserInvited as i32,
            &member.uuid,
            &org.uuid,
            &user.uuid,
            device.atype,
            &ip.ip,
            conn,
        )
        .await;

        if CONFIG.sso_org_auto_confirm() {
            if let Err(err) = auto_confirm_default_org_membership(user, device, ip, &org, member, conn).await {
                error!("Failed to auto-confirm default SSO organization membership for {}: {err}", user.email);
            }
            return Ok(());
        }

        if CONFIG.mail_enabled() {
            let mail_result = if member.status == MembershipStatus::Accepted as i32 {
                mail::send_enrolled(&user.email, &org.name).await
            } else {
                mail::send_invite(
                    user,
                    org.uuid.clone(),
                    member.uuid.clone(),
                    &org.name,
                    Some(org.billing_email.clone()),
                )
                .await
            };

            if let Err(err) = mail_result {
                error!("Failed to send SSO default org notification to {}: {err}", user.email);
            }
        }

        Ok(())
    }
}

// User has passed 2FA flow we can delete auth info from database
#[expect(clippy::too_many_arguments)]
pub async fn redeem(
    device: &Device,
    user: &User,
    ip: &ClientIp,
    client_id: Option<String>,
    sso_user: Option<SsoUser>,
    sso_auth: SsoAuth,
    auth_user: OIDCAuthenticatedUser,
    conn: &DbConn,
) -> ApiResult<AuthTokens> {
    sso_auth.delete(conn).await?;

    if sso_user.is_none() {
        let user_sso = SsoUser {
            user_uuid: user.uuid.clone(),
            identifier: auth_user.identifier.clone(),
        };
        user_sso.save(conn).await?;
    }

    reconcile_default_org_membership(user, device, ip, conn).await?;

    if CONFIG.sso_auth_only_not_session() {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    } else {
        let now = Utc::now();

        let (ap_nbf, ap_exp) =
            match (decode_token_claims("access_token", &auth_user.access_token), auth_user.expires_in) {
                (Ok(ap), _) => (ap.nbf(), ap.exp),
                (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
                _ => err!("Non jwt access_token and empty expires_in"),
            };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        create_auth_tokens_impl(device, auth_user.refresh_token, access_claims, auth_user.access_token)
    }
}

// We always return a refresh_token (with no refresh_token some secrets are not displayed in the web front).
// If there is no SSO refresh_token, we keep the access_token to be able to call user_info to check for validity
pub fn create_auth_tokens(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_token: Option<String>,
    access_token: String,
    expires_in: Option<Duration>,
) -> ApiResult<AuthTokens> {
    if CONFIG.sso_auth_only_not_session() {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    } else {
        let now = Utc::now();

        let (ap_nbf, ap_exp) = match (decode_token_claims("access_token", &access_token), expires_in) {
            (Ok(ap), _) => (ap.nbf(), ap.exp),
            (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
            _ => err!("Non jwt access_token and empty expires_in"),
        };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        create_auth_tokens_impl(device, refresh_token, access_claims, access_token)
    }
}

fn create_auth_tokens_impl(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: String,
) -> ApiResult<AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token {
        match decode_token_claims("refresh_token", &rt) {
            Err(_) => {
                let time_now = Utc::now();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {exp})");
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {refresh_payload:?}");
                (refresh_payload.nbf(), refresh_payload.exp, TokenWrapper::Refresh(rt))
            }
        }
    } else {
        debug!("No refresh_token present");
        (access_claims.nbf, access_claims.exp, TokenWrapper::Access(access_token))
    };

    let refresh_claims = auth::RefreshJwtClaims {
        nbf,
        exp,
        iss: auth::JWT_LOGIN_ISSUER.to_string(),
        sub: AuthMethod::Sso,
        device_token: device.refresh_token.clone(),
        token: Some(token),
    };

    Ok(AuthTokens {
        refresh_claims,
        access_claims,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_claims: auth::RefreshJwtClaims,
) -> ApiResult<AuthTokens> {
    let exp = refresh_claims.exp;
    match refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            // Use new refresh_token if returned
            let (new_refresh_token, access_token, expires_in) =
                Client::exchange_refresh_token(refresh_token.clone()).await?;

            create_auth_tokens(
                device,
                user,
                client_id,
                new_refresh_token.or(Some(refresh_token)),
                access_token,
                expires_in,
            )
        }
        Some(TokenWrapper::Access(access_token)) => {
            let now = Utc::now();
            let exp_limit = (now + *BW_EXPIRATION).timestamp();

            if exp < exp_limit {
                err_silent!("Access token is close to expiration but we have no refresh token")
            }

            Client::check_validity(access_token.clone()).await?;

            let access_claims = auth::LoginJwtClaims::new(
                device,
                user,
                now.timestamp(),
                exp,
                AuthMethod::Sso.scope_vec(),
                client_id,
                now,
            );

            create_auth_tokens_impl(device, None, access_claims, access_token)
        }
        None => err!("No token present while in SSO"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    #[test]
    fn encrypt_org_key_for_user_uses_bitwarden_rsa_oaep_sha1_cipher_string() {
        let rsa = Rsa::generate(2048).expect("test rsa key should be generated");
        let public_key = BASE64.encode(&rsa.public_key_to_der().expect("test public key should serialize"));
        let org_key = [7_u8; 64];

        let encrypted = encrypt_org_key_for_user(&org_key, &public_key).expect("org key should encrypt");
        let encrypted_payload = encrypted.strip_prefix("4.").expect("Bitwarden RSA-OAEP-SHA1 prefix is required");
        let encrypted_bytes = BASE64.decode(encrypted_payload.as_bytes()).expect("payload should be base64");

        let mut decrypted = vec![0; rsa.size() as usize];
        let decrypted_len = rsa
            .private_decrypt(&encrypted_bytes, &mut decrypted, Padding::PKCS1_OAEP)
            .expect("payload should decrypt with matching private key");
        decrypted.truncate(decrypted_len);

        assert_eq!(decrypted, org_key);
    }
}
