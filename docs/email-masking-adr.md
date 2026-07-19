# Email masking architecture gate

Status: **blocked pending an explicit trust and operations decision**.

Email masking is not an address-string generator. A usable alias must accept
mail and forward it, which requires either a third-party provider or a Bastion
mail service with domains, MX records, abuse handling, deliverability,
retention, deletion, and availability commitments.

The dashboard entry must remain unavailable until one of these models is
selected and reviewed. In either model:

- provider credentials must be stored only as encrypted reserved vault items;
- browser disk storage must never contain provider credentials or forwarding
  destinations derived from decrypted vault data;
- the UI must disclose that the mail operator can observe routing metadata and,
  absent end-to-end mail encryption, message contents;
- alias creation and deletion must be confirmed by the provider before local
  state changes are published;
- plus-addressing must not be described as masking because it exposes the real
  mailbox and is routinely normalized or rejected.
