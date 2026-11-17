// A NIP-46 *client* built on nostr-tools (an implementation independent of Embr), driving Embr as
// the remote signer. Prints one JSON object per line; exits non-zero on any failure.
//
//   node nip46_client.mjs bunker "<bunker://…>"        # signer-initiated flow
//   node nip46_client.mjs nostrconnect "<relay-url>"   # client-initiated flow (prints the URI first)
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex } from 'nostr-tools/utils';

const [mode, arg] = process.argv.slice(2);
const log = (o) => console.log(JSON.stringify(o));
const fail = (e) => { console.error('FAIL:', e?.stack ?? e); process.exit(1); };
process.on('unhandledRejection', fail);

const sk = generateSecretKey();
const pool = new SimplePool();
let signer;
let relays;
if (mode === 'bunker') {
  const bp = await parseBunkerInput(arg);
  relays = bp.relays;
  signer = BunkerSigner.fromBunker(sk, bp, { pool });
  await signer.connect({ name: 'nostr-tools interop', url: 'https://example.com' });
  log({ event: 'connected' });
} else if (mode === 'nostrconnect') {
  relays = [arg];
  const secret = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
  const uri = createNostrConnectURI({
    clientPubkey: getPublicKey(sk), relays, secret,
    name: 'nostr-tools nostrconnect', url: 'https://example.com', perms: ['sign_event:1', 'nip44_encrypt'],
  });
  log({ event: 'uri', uri }); // the harness imports this into Embr and approves it
  signer = await BunkerSigner.fromURI(sk, uri, { pool }, 60_000);
  log({ event: 'connected' });
} else {
  fail('usage: nip46_client.mjs bunker <uri> | nostrconnect <relay>');
}

const pubkey = await signer.getPublicKey();
log({ event: 'pubkey', pubkey });

const ev = await signer.signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [['t', 'interop']], content: 'hello from nostr-tools via Embr' });
if (!verifyEvent(ev) || ev.pubkey !== pubkey) fail('the event Embr signed does not verify in nostr-tools');
log({ event: 'signed', id: ev.id, pubkey: ev.pubkey });

const peerSk = generateSecretKey();
const ct = await signer.nip44Encrypt(getPublicKey(peerSk), 'secret from nostr-tools');
const pt = nip44.v2.decrypt(ct, nip44.v2.utils.getConversationKey(peerSk, pubkey));
if (pt !== 'secret from nostr-tools') fail('NIP-44 ciphertext from Embr does not decrypt in nostr-tools');
log({ event: 'encrypted', ok: true });

await signer.ping();
log({ event: 'pinged' });
await signer.close();
pool.close(relays);
log({ event: 'done' });
process.exit(0);
