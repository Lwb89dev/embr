// Generates tests/vectors/interop_nostr_tools.json using nostr-tools (an implementation
// independent of rust-nostr), so that Embr is tested against something other than itself.
//
//   npm ci --ignore-scripts && node gen_vectors.mjs
//
// Secrets below are throw-away test keys derived from fixed labels; never use them anywhere real.
import { createHash } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import * as nip49 from 'nostr-tools/nip49';
import * as nip19 from 'nostr-tools/nip19';

const here = dirname(fileURLToPath(import.meta.url));
const version = JSON.parse(readFileSync(join(here, 'node_modules/nostr-tools/package.json'))).version;

const key = (label) => new Uint8Array(createHash('sha256').update(`embr-interop/${label}`).digest());
const hex = (u8) => Buffer.from(u8).toString('hex');

const alice = key('alice');
const bob = key('bob');

const contents = [
  'hello nostr',
  '',
  'quote " backslash \\ newline \n cr \r tab \t bs \b ff \f',
  'unicode: 日本語 🔥 ünïcödé ‮ rtl, zwj 👨‍👩‍👧, del \u007f',
  'x'.repeat(5000),
];
const kinds = [0, 1, 4, 7, 14, 1059, 10002, 24133, 30023, 65535];

const events = [];
for (const [i, content] of contents.entries()) {
  const kind = kinds[i % kinds.length];
  const ev = finalizeEvent(
    {
      kind,
      created_at: 1700000000 + i,
      tags: [['e', 'a'.repeat(64), 'wss://relay.example'], ['alt', `case ${i} "q" \\ \n`], ['t']],
      content,
    },
    alice,
  );
  if (!verifyEvent(ev)) throw new Error('nostr-tools produced an event it cannot verify');
  events.push({ secret_hex: hex(alice), event: ev });
}

// Event with a C0 control character: nostr-tools escapes it as \u0001 (JSON.stringify); Embr only
// signs it when explicitly allowed, but must agree on the id.
const ctl = finalizeEvent({ kind: 1, created_at: 1700000000, tags: [], content: 'control \u0001 x' }, alice);
const ambiguous_control = { secret_hex: hex(alice), event: ctl };

const nip44v = [];
for (const plaintext of ['a', 'hello nostr', 'unicode 日本語 🔥', 'z'.repeat(1000), 'y'.repeat(65535)]) {
  const ck = nip44.getConversationKey(alice, getPublicKey(bob));
  nip44v.push({
    sender_secret_hex: hex(alice),
    recipient_pubkey_hex: getPublicKey(bob),
    plaintext,
    payload: nip44.encrypt(plaintext, ck),
  });
}

const nip04v = [];
for (const plaintext of ['legacy', 'unicode 日本語 🔥', 'w'.repeat(2000)]) {
  nip04v.push({
    sender_secret_hex: hex(alice),
    recipient_pubkey_hex: getPublicKey(bob),
    plaintext,
    payload: nip04.encrypt(alice, getPublicKey(bob), plaintext),
  });
}

const nip49v = [];
for (const password of ['nostr', 'correct horse battery staple', 'pässwörd ÅΩ']) {
  for (const ksb of [0x00, 0x01, 0x02]) {
    nip49v.push({
      secret_hex: hex(bob),
      password,
      log_n: 16,
      key_security_byte: ksb,
      ncryptsec: nip49.encrypt(bob, password, 16, ksb),
    });
  }
}

const nip19v = [
  { secret_hex: hex(alice), nsec: nip19.nsecEncode(alice), pubkey_hex: getPublicKey(alice), npub: nip19.npubEncode(getPublicKey(alice)) },
  { secret_hex: hex(bob), nsec: nip19.nsecEncode(bob), pubkey_hex: getPublicKey(bob), npub: nip19.npubEncode(getPublicKey(bob)) },
];

const out = {
  notice:
    'TEST-ONLY. Every key, password and ncryptsec in this file is a throw-away value derived from the public labels "embr-interop/alice" and "embr-interop/bob". They protect nothing. Never use them for a real identity.',
  generator: { name: 'nostr-tools', version },
  alice_pubkey_hex: getPublicKey(alice),
  bob_pubkey_hex: getPublicKey(bob),
  events,
  ambiguous_control,
  nip44: nip44v,
  nip04: nip04v,
  nip49: nip49v,
  nip19: nip19v,
};
const dest = join(here, '..', 'vectors', 'interop_nostr_tools.json');
writeFileSync(dest, JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${dest} (nostr-tools ${version}): ${events.length} events, ${nip44v.length} nip44, ${nip04v.length} nip04, ${nip49v.length} nip49`);
