# Field-transform hooks in the data layer (encrypt / tokenize / redact selected fields)

## Summary

Add a small, opt-in extension point that lets a plugin or module transform selected fields on the way into MongoDB and on the way back out to a client. One registration point, consulted in three places the data already flows through: the model write path, the model read path, and the real-time message stream. The obvious first use is sealing a message's `msg` so the database holds ciphertext, but the same seam covers tokenization and role-based redaction of any field.

This is deliberately vendor-neutral. The framework would ship the hook, not any particular crypto or provider.

## Motivation

A chat server's most sensitive data is the message text itself, plus the personal fields around it. A growing number of self-hosted deployments want some of that to be ciphertext at rest (or tokenized, or redacted for people without a role), while the app keeps working with plaintext in-request. Concrete cases:

- **Field-level encryption** against an external KMS, an HSM, or a threshold-crypto network, so a stolen database or a leaked backup is unreadable and the server process never holds a standing key.
- **Tokenization** of PII for compliance scope reduction, detokenized per request.
- **Role-gated redaction**, where a field reads back as plaintext for a user who holds a role and masked for one who does not.

All three are the same operation: transform a value before it is persisted, and transform it back (or not) when it is read, based on who is reading.

## The problem today

There is no extension point for this, so doing it means patching core in three places:

- **Write:** `BaseRaw` in `@rocket.chat/models` (`insertOne`/`insertMany`/`updateOne`), to transform the configured fields before they reach the collection.
- **Read (history):** the message read path. Nearly every REST and method read of messages funnels through `normalizeMessagesForUser` (and under it, the `BaseRaw` finders), so one hook there covers history loads, search, threads, pinned, and so on.
- **Read (real-time):** the new-message broadcast. `listeners.module.ts` handles `watch.messages` and fans a single serialized payload out to every room subscriber (`streamRoomMessage.emitWithoutBroadcast(rid, message)`), so a message opened once for everyone would leak to a recipient who lacks the role. It has to be transformed per recipient.

That works, but it means forking `@rocket.chat/meteor` and `@rocket.chat/models`, which cannot ship as a plugin and is brittle across upgrades. The change itself is small; the blocker is only that the seams are not exposed.

## Proposal

A registry of field transformers, consulted by the data layer. A transformer names the collection fields it owns and implements up to two async hooks:

```ts
interface FieldTransformer {
  // collection name -> field names, e.g. { message: ['msg'] }
  fields: Record<string, string[]>;

  // before a document/update is persisted; return the value to store
  onWrite?(ctx: FieldHookContext): Promise<unknown> | unknown;

  // after a document is read, before it is returned to a user; return the value to expose
  onRead?(ctx: FieldHookContext): Promise<unknown> | unknown;
}

interface FieldHookContext {
  collection: string;   // 'message'
  field: string;        // 'msg'
  value: unknown;       // plaintext on write, stored value on read
  record: Record<string, unknown>;
  userId?: string;      // the reader, on read
}
```

Registration is opt-in. When nothing is registered every path is a no-op, so a stock server is unchanged behind a single guard.

### Where it hooks

1. **Write** in `BaseRaw#insertOne`/`insertMany`/`updateOne`, for each field a transformer owns.
2. **Read (history)** in the message read path. Consuming the hook in `normalizeMessagesForUser` (which already receives the reader's `uid`) covers the REST and method reads in one place; alternatively the `BaseRaw` finders, restricted to the `message` collection.
3. **Read (real-time)** by letting a transformer register into the streamer's existing per-subscription transform. RC already has this seam: `Streamer.sendToManySubscriptions` calls a `TransformMessage` callback once per subscription, and it is used today for the `__my_messages__` stream. Each subscription carries its recipient's `userId`. The ask is to route the room `watch.messages` emit through that same per-subscription transform so a plugin can open (or not) the message for each recipient. No new streamer machinery is needed.

The real-time transform is synchronous, so a plugin that opens over a network pre-computes per connected recipient in the async `watch.messages` handler and the transform just selects the right payload. That is a plugin concern, not a framework one.

### Request context

Read transforms are per-user: open this field as the user this request authenticated, if they hold the role. The reader is already available at each seam. In methods it is `Meteor.userId()`/`this.userId`; in REST it is `this.userId`; `normalizeMessagesForUser` already gets `uid`; the streamer subscription carries `_session.userId`. A plugin threads that to its backend (for example via `AsyncLocalStorage`), so the framework only needs to pass the `userId` it already has into the hook.

### Batching

A transformer that talks to a network wants to batch a page of messages into one round trip rather than one call per field. Worth supporting a batched form the data layer prefers when present (`onReadMany` / `onWriteMany`), so a history load or a page of results is one round trip.

## Example plugin (one implementation, not part of core)

```ts
{
  fields: { message: ['msg'] },
  async onWriteMany(ctxs) { /* seal each value via the configured backend */ },
  async onReadMany(ctxs) {
    // open, gated on the request's verified user holding a role;
    // with no context or no authorization, return the stored (sealed) value unchanged.
  },
}
```

The backend is the plugin's business (a KMS, Vault, an HSM, a threshold-crypto network, in-process AES with envelope keys). Core stays vendor-neutral.

## Non-goals

- No opinion on crypto, key management, or providers.
- No search or sort on transformed fields. A sealed field is opaque to Mongo queries, the same as for any field-level-encryption scheme. Which fields to register is the deployment's call, and routing keys (rid, u._id, ts) stay in the clear by that choice. Text search over sealed message bodies is out of scope.
- No migration tooling for existing rows; a plugin can backfill through the same hook.

## Backward compatibility

Fully additive and opt-in. With no transformers registered, the write, read, and stream paths behave exactly as today, behind a single guard. No schema changes.

## Prior art / reference

We built this end to end against a fork, sealing message `msg` with an external threshold-crypto backend, gated by a role, opened per request on history reads and per recipient on the live stream. The whole change is small and lives in the three `BaseRaw` write methods, one line in `normalizeMessagesForUser`, and the `watch.messages` emit (reusing the existing `TransformMessage` seam plus a small accessor for a room's connected subscribers). Happy to open a draft PR that adds just the seam, no vendor code, if there is appetite for it.
