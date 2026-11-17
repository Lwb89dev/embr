// Verifies, with nostr-tools, everything the Rust test `emit_for_nostr_tools` produced.
//
//   node verify_rust.mjs ../../target/interop/rust_out.json
import { readFileSync } from 'node:fs';
import { verifyEvent, getPublicKey } from 'nostr-tools/pure';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import * as nip49 from 'nostr-tools/nip49';
import * as nip19 from 'nostr-tools/nip19';

const path = process.argv[2];
if (!path) throw new Error('usage: node verify_rust.mjs <rust_out.json>');
const data = JSON.parse(readFileSync(path, 'utf8'));
const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

let checks = 0;
const ok = (cond, what) => {
  if (!cond) {
    console.error(`FAIL: ${what}`);
    process.exit(1);
  }
  checks++;
};

for (const [i, ev] of data.events.entries()) {
  ok(verifyEvent(ev), `event #${i} (kind ${ev.kind}) verifies in nostr-tools`);
}
for (const [i, v] of data.nip44.entries()) {
  const ck = nip44.getConversationKey(unhex(v.recipient_secret_hex), v.sender_pubkey_hex);
  ok(nip44.decrypt(v.payload, ck) === v.plaintext, `nip44 #${i} decrypts in nostr-tools`);
}
for (const [i, v] of data.nip04.entries()) {
  ok(nip04.decrypt(unhex(v.recipient_secret_hex), v.sender_pubkey_hex, v.payload) === v.plaintext, `nip04 #${i} decrypts in nostr-tools`);
}
for (const [i, v] of data.nip49.entries()) {
  const sk = nip49.decrypt(v.ncryptsec, v.password);
  ok(Buffer.from(sk).toString('hex') === v.secret_hex, `ncryptsec #${i} decrypts in nostr-tools`);
}
for (const [i, v] of data.nip19.entries()) {
  const d = nip19.decode(v.nsec);
  ok(d.type === 'nsec' && Buffer.from(d.data).toString('hex') === v.secret_hex, `nsec #${i} decodes in nostr-tools`);
  ok(nip19.decode(v.npub).data === v.pubkey_hex, `npub #${i} decodes in nostr-tools`);
  ok(getPublicKey(unhex(v.secret_hex)) === v.pubkey_hex, `pubkey #${i} derivation agrees`);
}
console.log(`OK: nostr-tools accepted ${checks} artefacts produced by Embr`);
