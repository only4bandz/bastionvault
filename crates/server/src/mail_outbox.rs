//! Durable, at-least-once transactional email delivery.
//!
//! Producers insert mail in the same SQLite transaction as the state that
//! requires it. The async worker leases one row at a time, releases SQLite
//! before network I/O, and acknowledges only after the SMTP relay accepts the
//! message. A crash in that final gap can duplicate delivery, so the stable
//! Message-ID is preserved across every attempt.

use std::time::Duration;

use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::Address;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::{now_secs, Db, DbError};

const LEASE_SECONDS: i64 = 60;
const IDLE_POLL: Duration = Duration::from_secs(5);
const ERROR_POLL: Duration = Duration::from_secs(5);
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATTEMPTS: i64 = 8;
const BASE_RETRY_SECONDS: i64 = 30;
const MAX_RETRY_SECONDS: i64 = 6 * 60 * 60;

const MAX_RECIPIENT_BYTES: usize = 254;
const MAX_SUBJECT_BYTES: usize = 160;
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_GLOBAL: i64 = 10_000;
const MAX_ACTIVE_PER_OWNER: i64 = 3;

pub(super) struct MailDraft<'a> {
    pub id: &'a str,
    pub recipient: &'a str,
    pub subject: &'a str,
    pub text_body: &'a str,
    pub created_at: i64,
}

pub(super) fn valid_recipient(value: &str) -> bool {
    value.len() <= MAX_RECIPIENT_BYTES
        && value
            .parse::<Address>()
            .is_ok_and(|address| address.to_string() == value)
}

/// Insert mail while the producer's authoritative SQLite transaction is still
/// open. Returns false when the bounded active queue is full.
/// Takes a plain `&Connection` so callers may enqueue inside a transaction or
/// a savepoint (both deref to `Connection`); it must never run outside one.
pub(super) fn enqueue_registration(
    tx: &rusqlite::Connection,
    challenge_email: &str,
    draft: MailDraft<'_>,
) -> rusqlite::Result<bool> {
    if draft.id.len() != 32
        || !draft
            .id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !valid_recipient(draft.recipient)
        || draft.subject.is_empty()
        || draft.subject.len() > MAX_SUBJECT_BYTES
        || draft.text_body.is_empty()
        || draft.text_body.len() > MAX_BODY_BYTES
        || draft.created_at < 0
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let active_global: i64 = tx.query_row(
        "SELECT COUNT(*) FROM mail_outbox WHERE state IN ('pending','in_flight')",
        [],
        |row| row.get(0),
    )?;
    let active_owner: i64 = tx.query_row(
        "SELECT COUNT(*) FROM mail_outbox
          WHERE challenge_email=?1 AND state IN ('pending','in_flight')",
        [challenge_email],
        |row| row.get(0),
    )?;
    if active_global >= MAX_ACTIVE_GLOBAL || active_owner >= MAX_ACTIVE_PER_OWNER {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO mail_outbox(
           id,account_email,challenge_email,recipient,subject,text_body,state,
           attempts,available_at,created_at
         ) VALUES(?1,?2,?3,?4,?5,?6,'pending',0,?7,?7)",
        params![
            draft.id,
            Option::<&str>::None,
            challenge_email,
            draft.recipient,
            draft.subject,
            draft.text_body,
            draft.created_at
        ],
    )?;
    Ok(true)
}

pub(super) struct SmtpConfig {
    host: String,
    port: u16,
    username: String,
    password: Zeroizing<String>,
    from: Mailbox,
}

impl SmtpConfig {
    pub(super) fn from_lookup(
        lookup: &mut impl FnMut(&str) -> Option<String>,
    ) -> Result<Option<Self>, String> {
        let host = lookup("BASTION_SMTP_HOST");
        let port = lookup("BASTION_SMTP_PORT");
        let username = lookup("BASTION_SMTP_USERNAME");
        // Wrap the environment-owned allocation immediately so every
        // validation error path erases it on drop.
        let password = lookup("BASTION_SMTP_PASSWORD").map(Zeroizing::new);
        let from = lookup("BASTION_MAIL_FROM");
        if host.is_none()
            && port.is_none()
            && username.is_none()
            && password.is_none()
            && from.is_none()
        {
            return Ok(None);
        }

        let required = |name: &str, value: Option<String>| {
            value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("{name} is required when SMTP mail is configured"))
        };
        let host = required("BASTION_SMTP_HOST", host)?;
        if !host.is_ascii() || host.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err("BASTION_SMTP_HOST must be an ASCII hostname".to_string());
        }
        let port = required("BASTION_SMTP_PORT", port)?
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "BASTION_SMTP_PORT must be an integer from 1 to 65535".to_string())?;
        let username = required("BASTION_SMTP_USERNAME", username)?;
        let password = password
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                "BASTION_SMTP_PASSWORD is required when SMTP mail is configured".to_string()
            })?;
        let from = required("BASTION_MAIL_FROM", from)?
            .parse::<Mailbox>()
            .map_err(|_| "BASTION_MAIL_FROM must be one valid mailbox".to_string())?;
        let config = Self {
            host,
            port,
            username,
            password,
            from,
        };
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
            .map_err(|_| "BASTION_SMTP_HOST is not a valid STARTTLS relay".to_string())?;
        Ok(Some(config))
    }

    fn build_transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
            .map_err(|_| "BASTION_SMTP_HOST is not a valid STARTTLS relay".to_string())
            .map(|builder| {
                builder
                    .port(self.port)
                    // lettre retains the one operational credential copy used
                    // for reconnects. The Zeroizing configuration allocation
                    // is erased as soon as SmtpSender construction completes.
                    .credentials(Credentials::new(
                        self.username.clone(),
                        self.password.as_str().to_owned(),
                    ))
                    .timeout(Some(SMTP_TIMEOUT))
                    .build()
            })
    }
}

#[derive(Clone, Debug)]
struct MailJob {
    id: String,
    recipient: String,
    subject: String,
    text_body: String,
    attempt: i64,
}

#[derive(Clone, Copy, Debug)]
enum DeliveryFailure {
    Retryable(&'static str),
    Permanent(&'static str),
}

trait MailSender: Send + Sync {
    async fn send(&self, job: &MailJob) -> Result<(), DeliveryFailure>;
}

struct SmtpSender {
    from: Mailbox,
    message_id_domain: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpSender {
    fn new(config: SmtpConfig) -> Result<Self, String> {
        let message_id_domain = config
            .from
            .email
            .to_string()
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_string())
            .ok_or_else(|| "BASTION_MAIL_FROM must contain a domain".to_string())?;
        let transport = config.build_transport()?;
        Ok(Self {
            from: config.from,
            message_id_domain,
            transport,
        })
    }
}

impl MailSender for SmtpSender {
    async fn send(&self, job: &MailJob) -> Result<(), DeliveryFailure> {
        let recipient = job
            .recipient
            .parse::<Mailbox>()
            .map_err(|_| DeliveryFailure::Permanent("invalid_recipient"))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .message_id(Some(format!(
                "<bastion-{}@{}>",
                job.id, self.message_id_domain
            )))
            .subject(&job.subject)
            .header(ContentType::TEXT_PLAIN)
            .body(job.text_body.clone())
            .map_err(|_| DeliveryFailure::Permanent("invalid_message"))?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.is_permanent() {
                    DeliveryFailure::Permanent("smtp_permanent")
                } else {
                    DeliveryFailure::Retryable("smtp_transient")
                }
            })
    }
}

pub(super) fn spawn(db: Db, config: SmtpConfig) {
    tokio::spawn(async move {
        let sender = match SmtpSender::new(config) {
            Ok(sender) => sender,
            Err(_) => {
                tracing::error!("mail worker configuration failed after startup validation");
                return;
            }
        };
        tracing::info!("mail worker started");
        loop {
            match deliver_one_at(&db, &sender, now_secs()).await {
                Ok(true) => {}
                Ok(false) => tokio::time::sleep(IDLE_POLL).await,
                Err(_) => {
                    tracing::error!("mail outbox storage operation failed");
                    tokio::time::sleep(ERROR_POLL).await;
                }
            }
        }
    });
}

async fn deliver_one_at(db: &Db, sender: &impl MailSender, now: i64) -> Result<bool, DbError> {
    let Some(job) = claim_one(db, now).await? else {
        return Ok(false);
    };
    let result = sender.send(&job).await;
    let outcome = match &result {
        Ok(()) => ("accepted", None),
        Err(DeliveryFailure::Permanent(code)) => ("permanent_failure", Some(*code)),
        Err(DeliveryFailure::Retryable(code)) if job.attempt >= MAX_ATTEMPTS => {
            ("attempts_exhausted", Some(*code))
        }
        Err(DeliveryFailure::Retryable(code)) => ("retry_scheduled", Some(*code)),
    };
    finish_attempt(db, &job, result, now).await?;
    match outcome {
        ("accepted", _) => {
            tracing::info!(attempt = job.attempt, outcome = outcome.0, "mail delivery")
        }
        ("retry_scheduled", Some(code)) => tracing::warn!(
            attempt = job.attempt,
            outcome = outcome.0,
            error_code = code,
            "mail delivery"
        ),
        (_, Some(code)) => tracing::error!(
            attempt = job.attempt,
            outcome = outcome.0,
            error_code = code,
            "mail delivery"
        ),
        _ => unreachable!("delivery outcomes are exhaustive"),
    }
    Ok(true)
}

async fn claim_one(db: &Db, now: i64) -> Result<Option<MailJob>, DbError> {
    db.call_mutation(move |conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Expired pre-registration challenges are useless and their outbox
        // rows cascade away before they can emit stale verification links.
        tx.execute(
            "DELETE FROM registration_challenges WHERE expires_at<?1",
            [now],
        )?;
        // A crash can leave the final allowed attempt leased. Once that lease
        // expires, stop instead of creating an unbounded ninth delivery. The
        // stable Message-ID still gives the relay/recipient a dedupe key if the
        // eighth attempt was accepted before the acknowledgement was lost.
        tx.execute(
            "UPDATE mail_outbox
                SET state='dead',recipient='',subject='',text_body='',
                    lease_until=NULL,last_error_code='attempts_exhausted'
              WHERE state='in_flight' AND lease_until<=?1 AND attempts>=?2",
            params![now, MAX_ATTEMPTS],
        )?;
        let row = tx
            .query_row(
                "SELECT id,recipient,subject,text_body,attempts
                   FROM mail_outbox
                  WHERE (state='pending' AND available_at<=?1)
                     OR (state='in_flight' AND lease_until<=?1 AND attempts<?2)
                  ORDER BY created_at,id
                  LIMIT 1",
                params![now, MAX_ATTEMPTS],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, recipient, subject, text_body, attempts)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || recipient.is_empty()
            || recipient.len() > MAX_RECIPIENT_BYTES
            || subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || text_body.is_empty()
            || text_body.len() > MAX_BODY_BYTES
            || !(0..MAX_ATTEMPTS).contains(&attempts)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let attempt = attempts + 1;
        let updated = tx.execute(
            "UPDATE mail_outbox
                SET state='in_flight',attempts=?1,lease_until=?2,last_error_code=NULL
              WHERE id=?3",
            params![attempt, now.saturating_add(LEASE_SECONDS), id],
        )?;
        if updated != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        tx.commit()?;
        Ok(Some(MailJob {
            id,
            recipient,
            subject,
            text_body,
            attempt,
        }))
    })
    .await
}

async fn finish_attempt(
    db: &Db,
    job: &MailJob,
    result: Result<(), DeliveryFailure>,
    now: i64,
) -> Result<(), DbError> {
    let id = job.id.clone();
    let attempt = job.attempt;
    db.call_mutation(move |conn| {
        let updated = match result {
            Ok(()) => conn.execute(
                "UPDATE mail_outbox
                    SET state='delivered',recipient='',subject='',text_body='',
                        lease_until=NULL,delivered_at=?1,last_error_code=NULL
                  WHERE id=?2 AND state='in_flight' AND attempts=?3",
                params![now, id, attempt],
            )?,
            Err(DeliveryFailure::Permanent(code)) => conn.execute(
                "UPDATE mail_outbox
                    SET state='dead',recipient='',subject='',text_body='',
                        lease_until=NULL,last_error_code=?1
                  WHERE id=?2 AND state='in_flight' AND attempts=?3",
                params![code, id, attempt],
            )?,
            Err(DeliveryFailure::Retryable(_)) if attempt >= MAX_ATTEMPTS => conn.execute(
                "UPDATE mail_outbox
                    SET state='dead',recipient='',subject='',text_body='',
                        lease_until=NULL,last_error_code='attempts_exhausted'
                  WHERE id=?1 AND state='in_flight' AND attempts=?2",
                params![id, attempt],
            )?,
            Err(DeliveryFailure::Retryable(code)) => {
                let exponent = u32::try_from(attempt.saturating_sub(1))
                    .unwrap_or(0)
                    .min(20);
                let delay = BASE_RETRY_SECONDS
                    .saturating_mul(1_i64 << exponent)
                    .min(MAX_RETRY_SECONDS);
                conn.execute(
                    "UPDATE mail_outbox
                        SET state='pending',available_at=?1,lease_until=NULL,last_error_code=?2
                      WHERE id=?3 AND state='in_flight' AND attempts=?4",
                    params![now.saturating_add(delay), code, id, attempt],
                )?
            }
        };
        if updated != 1 {
            let still_exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM mail_outbox WHERE id=?1)",
                [&id],
                |row| row.get(0),
            )?;
            if still_exists {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeSender {
        results: Mutex<VecDeque<Result<(), DeliveryFailure>>>,
        delivered_ids: Mutex<Vec<String>>,
    }

    impl FakeSender {
        fn new(results: impl IntoIterator<Item = Result<(), DeliveryFailure>>) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                delivered_ids: Mutex::new(Vec::new()),
            }
        }
    }

    impl MailSender for FakeSender {
        async fn send(&self, job: &MailJob) -> Result<(), DeliveryFailure> {
            self.delivered_ids.lock().unwrap().push(job.id.clone());
            self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }

    async fn insert_mail(db: &Db, id: &str, now: i64) {
        let id = id.to_string();
        db.call_mutation(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO accounts(
                   email,salt,kdf,wrapped_vault_key,auth_hash
                 ) VALUES('alice@example.com','salt','{}','{}','hash')",
                [],
            )?;
            conn.execute(
                "INSERT INTO mail_outbox(
                   id,account_email,challenge_email,recipient,subject,text_body,state,attempts,
                   available_at,created_at
                 ) VALUES(?1,'alice@example.com',NULL,'alice@example.com',
                          'Verify your Bastion account','verification body',
                          'pending',0,?2,?2)",
                params![id, now],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn row(db: &Db, id: &str) -> (String, String, i64, i64, Option<i64>, Option<String>) {
        let id = id.to_string();
        db.call(move |conn| {
            conn.query_row(
                "SELECT state,recipient,attempts,available_at,delivered_at,last_error_code
                   FROM mail_outbox WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
        })
        .await
        .unwrap()
    }

    fn draft_for<'a>(id: &'a str, recipient: &'a str, now: i64) -> MailDraft<'a> {
        MailDraft {
            id,
            recipient,
            subject: "Verify your Bastion account",
            text_body: "verification body",
            created_at: now,
        }
    }

    /// The per-owner cap is what stops one mailbox from occupying the queue.
    /// It is enforced only by unread code, so it is pinned here.
    #[tokio::test]
    async fn one_owner_cannot_occupy_more_than_its_share_of_the_outbox() {
        let (db, _, _) = Db::open(":memory:");
        let accepted = db
            .call_mutation(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                // Queued registration mail is owned by a challenge row.
                for (index, owner) in ["crowder@example.com", "other@example.com"]
                    .into_iter()
                    .enumerate()
                {
                    tx.execute(
                        "INSERT INTO registration_challenges(
                           email,token_hash,expires_at,resend_after,verified_at,created_at
                         ) VALUES(?1,?2,?3,?4,NULL,?5)",
                        params![owner, [index as u8; 32].as_slice(), 10_000, 100, 100],
                    )?;
                }
                let mut accepted = Vec::new();
                for attempt in 0..(MAX_ACTIVE_PER_OWNER + 1) {
                    let id = format!("{:032x}", attempt);
                    accepted.push(enqueue_registration(
                        &tx,
                        "crowder@example.com",
                        draft_for(&id, "crowder@example.com", 100),
                    )?);
                }
                // A different owner is unaffected by the first one's usage.
                let other = enqueue_registration(
                    &tx,
                    "other@example.com",
                    draft_for("ffffffffffffffffffffffffffffffff", "other@example.com", 100),
                )?;
                tx.commit()?;
                Ok((accepted, other))
            })
            .await
            .unwrap();
        let (owner_results, other) = accepted;

        assert_eq!(
            owner_results,
            vec![true, true, true, false],
            "the per-owner outbox cap did not hold"
        );
        assert!(other, "one owner's cap must not block another owner");
    }

    #[tokio::test]
    async fn accepted_mail_is_scrubbed_after_delivery() {
        let (db, _, _) = Db::open(":memory:");
        let id = "00112233445566778899aabbccddeeff";
        insert_mail(&db, id, 100).await;
        let sender = FakeSender::new([Ok(())]);

        assert!(deliver_one_at(&db, &sender, 100).await.unwrap());
        assert!(!deliver_one_at(&db, &sender, 100).await.unwrap());
        assert_eq!(
            row(&db, id).await,
            (
                "delivered".to_string(),
                String::new(),
                1,
                100,
                Some(100),
                None
            )
        );
    }

    #[tokio::test]
    async fn transient_failure_retries_with_the_same_stable_id() {
        let (db, _, _) = Db::open(":memory:");
        let id = "11112222333344445555666677778888";
        insert_mail(&db, id, 200).await;
        let sender = FakeSender::new([Err(DeliveryFailure::Retryable("temporary")), Ok(())]);

        assert!(deliver_one_at(&db, &sender, 200).await.unwrap());
        let pending = row(&db, id).await;
        assert_eq!(pending.0, "pending");
        assert_eq!(pending.2, 1);
        assert_eq!(pending.3, 230);
        assert_eq!(pending.5.as_deref(), Some("temporary"));
        assert!(!deliver_one_at(&db, &sender, 229).await.unwrap());
        assert!(deliver_one_at(&db, &sender, 230).await.unwrap());
        assert_eq!(sender.delivered_ids.lock().unwrap().as_slice(), [id, id]);
    }

    #[tokio::test]
    async fn expired_lease_is_recovered_and_permanent_failure_is_scrubbed() {
        let (db, _, _) = Db::open(":memory:");
        let id = "aaaabbbbccccddddeeeeffff00001111";
        insert_mail(&db, id, 300).await;

        let first = claim_one(&db, 300).await.unwrap().unwrap();
        assert_eq!(first.attempt, 1);
        assert!(claim_one(&db, 359).await.unwrap().is_none());
        let recovered = claim_one(&db, 360).await.unwrap().unwrap();
        assert_eq!(recovered.id, first.id);
        assert_eq!(recovered.attempt, 2);
        finish_attempt(
            &db,
            &recovered,
            Err(DeliveryFailure::Permanent("rejected")),
            360,
        )
        .await
        .unwrap();

        let dead = row(&db, id).await;
        assert_eq!(dead.0, "dead");
        assert_eq!(dead.1, "");
        assert_eq!(dead.2, 2);
        assert_eq!(dead.5.as_deref(), Some("rejected"));
    }

    #[tokio::test]
    async fn expired_final_attempt_is_not_delivered_a_ninth_time() {
        let (db, _, _) = Db::open(":memory:");
        let id = "9999aaaabbbbccccddddeeeeffff0000";
        insert_mail(&db, id, 400).await;
        let id_for_update = id.to_string();
        db.call_mutation(move |conn| {
            conn.execute(
                "UPDATE mail_outbox SET attempts=?1 WHERE id=?2",
                params![MAX_ATTEMPTS - 1, id_for_update],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let final_attempt = claim_one(&db, 400).await.unwrap().unwrap();
        assert_eq!(final_attempt.attempt, MAX_ATTEMPTS);
        assert!(claim_one(&db, 459).await.unwrap().is_none());
        assert!(claim_one(&db, 460).await.unwrap().is_none());

        let dead = row(&db, id).await;
        assert_eq!(dead.0, "dead");
        assert_eq!(dead.1, "");
        assert_eq!(dead.2, MAX_ATTEMPTS);
        assert_eq!(dead.5.as_deref(), Some("attempts_exhausted"));
    }
}
