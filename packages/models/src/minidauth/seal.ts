/**
 * minidauth field sealing for Rocket.Chat (MongoDB models layer).
 *
 * Seals selected fields (by default a message's `msg` text) with minidauth before they reach MongoDB,
 * and opens them again on the way out. The crypto runs in the minidauth-seal sidecar, which talks to
 * minidauth and the Tide ORK cohort: this app, and Mongo, only ever hold ciphertext. The vendor key
 * lives as threshold shares across the ORK network and is never assembled here, so a stolen database
 * or a leaked backup is unreadable, and a quorum (not this app) decides whether a message can be read
 * at all (the reader must hold a quorum-granted role, or `open` returns nothing and the field stays
 * sealed).
 *
 * Off by default. Set MINIDAUTH_SEAL_URL to point at the sidecar to turn it on; unset, every path here
 * is a no-op and Rocket.Chat behaves exactly like upstream.
 *
 * Proof of concept. It batches: a page of messages opens in a single cohort fan-out, not one round
 * trip per message. Sealed columns hold ciphertext, so Mongo cannot text-search or sort on them, which
 * is why only the message body is sealed and routing keys (rid, u._id, ts) stay in the clear.
 */
import { currentReaderToken } from './reader';

// Mongo collection name -> the scalar string fields to seal on documents in that collection.
const SEALED: Record<string, string[]> = {
	message: ['msg'],
};

// Derived plaintext copies to remove on write, keyed by MODEL name. Rocket.Chat pre-parses a message
// into `md` (a markdown AST that still holds the plaintext) and the client renders `md` when present,
// so sealing `msg` alone would leak the text through `md`. Dropping it makes the client re-parse the
// sealed-or-opened `msg` instead. Applied wherever the model has sealed fields.
const DROP_ON_WRITE: Record<string, string[]> = {
	message: ['md'],
};

const MARKER = 'ms1:'; // a sealed string value is "ms1:<ciphertextB64>"
const isSealed = (v: unknown): v is string => typeof v === 'string' && v.startsWith(MARKER);

const sealUrl = (): string | undefined => process.env.MINIDAUTH_SEAL_URL;
export const minidauthEnabled = (): boolean => Boolean(sealUrl());

/** Which fields (if any) this collection seals. */
export const sealedFields = (collection: string): string[] => SEALED[collection] || [];

async function sidecar(path: string, body: unknown, bearer?: string): Promise<any> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (bearer) {
		headers.Authorization = `Bearer ${bearer}`; // the reader's delegation token, on /open
	}
	const r = await fetch(sealUrl() + path, { method: 'POST', headers, body: JSON.stringify(body) });
	const text = await r.text();
	if (!r.ok) {
		throw new Error(`minidauth-seal ${path} -> ${r.status} ${text}`);
	}
	return text ? JSON.parse(text) : {};
}

// A leaf is one string value we can read and write in place, so the same code seals and opens it.
type Leaf = { get: () => unknown; set: (v: unknown) => void };
const leaf = (obj: any, key: string): Leaf => ({ get: () => obj[key], set: (v) => (obj[key] = v) });

// Seal fails closed: if the sidecar is unreachable, the write throws rather than storing plaintext.
async function sealLeaves(leaves: Leaf[]): Promise<void> {
	if (leaves.length === 0) {
		return;
	}
	const fields: Record<string, string> = {};
	leaves.forEach((l, i) => (fields[String(i)] = l.get() as string));
	// The sidecar returns marker-included values (it decides what is real ciphertext); store as-is.
	const { sealed } = await sidecar('/seal', { fields });
	leaves.forEach((l, i) => l.set((sealed as Record<string, string>)[String(i)]));
}

let openWarned = false;
// Open is best-effort and gated on the reader: decryption runs as the end user named in a token this
// request carries (withMinidauthReader), and only if minidauth's quorum grant says that user holds the
// reading role. No reader in context, an ungranted reader, or a sidecar that is down all leave the
// field sealed rather than crashing the read. Ciphertext is the safe failure.
async function openLeaves(leaves: Leaf[]): Promise<void> {
	if (leaves.length === 0) {
		return;
	}
	const readerToken = currentReaderToken();
	if (!readerToken) {
		if (!openWarned) {
			openWarned = true;
			console.warn('[minidauth-seal] no reader identity in context; leaving messages sealed');
		}
		return;
	}
	try {
		const fields: Record<string, string> = {};
		leaves.forEach((l, i) => (fields[String(i)] = (l.get() as string).slice(MARKER.length)));
		const { fields: opened } = await sidecar('/open', { fields }, readerToken); // one cohort fan-out
		leaves.forEach((l, i) => l.set((opened as Record<string, string>)[String(i)]));
	} catch (e) {
		if (!openWarned) {
			openWarned = true;
			console.warn('[minidauth-seal] leaving messages sealed:', (e as Error).message);
		}
	}
}

const collectPlaintextLeaves = (collection: string, carrier: any, out: Leaf[]): void => {
	if (!carrier || typeof carrier !== 'object') {
		return;
	}
	for (const f of sealedFields(collection)) {
		const v = carrier[f];
		if (typeof v === 'string' && v.length > 0) {
			out.push(leaf(carrier, f));
		}
	}
};

const dropDerived = (collection: string, carrier: any): void => {
	if (!carrier || typeof carrier !== 'object') {
		return;
	}
	for (const f of DROP_ON_WRITE[collection] || []) {
		if (f in carrier) {
			delete carrier[f];
		}
	}
};

/** Seal the configured fields on documents about to be inserted. Mutates in place. */
export async function sealInsert(collection: string, docs: any | any[]): Promise<void> {
	if (!minidauthEnabled() || sealedFields(collection).length === 0) {
		return;
	}
	const out: Leaf[] = [];
	for (const doc of Array.isArray(docs) ? docs : [docs]) {
		collectPlaintextLeaves(collection, doc, out);
		dropDerived(collection, doc);
	}
	await sealLeaves(out);
}

/** Seal the configured fields inside a Mongo update ($set.<field> or a bare <field>). Mutates in place. */
export async function sealUpdate(collection: string, update: any): Promise<void> {
	if (!minidauthEnabled() || sealedFields(collection).length === 0 || !update || typeof update !== 'object') {
		return;
	}
	const out: Leaf[] = [];
	collectPlaintextLeaves(collection, update.$set, out);
	collectPlaintextLeaves(collection, update, out); // a direct-field replacement style update
	await sealLeaves(out);
	// remove derived plaintext copies from whichever shape the update uses
	dropDerived(collection, update.$set);
	dropDerived(collection, update);
}

/** Open the configured sealed fields on documents just read from Mongo. Mutates in place. */
export async function openForRead(collection: string, docs: any | any[]): Promise<void> {
	if (!minidauthEnabled() || !docs || sealedFields(collection).length === 0) {
		return;
	}
	const out: Leaf[] = [];
	for (const doc of Array.isArray(docs) ? docs : [docs]) {
		if (!doc || typeof doc !== 'object') {
			continue;
		}
		for (const f of sealedFields(collection)) {
			if (isSealed(doc[f])) {
				out.push(leaf(doc, f));
			}
		}
	}
	await openLeaves(out);
}
