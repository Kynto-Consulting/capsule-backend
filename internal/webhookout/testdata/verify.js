// Verifies a Git Capsule webhook delivery. Node 18+, no dependencies.
//
//   node verify.js            reads the delivery from the environment:
//     CAPSULE_SECRET          your current signing secret (whsec_...)
//     CAPSULE_SECRET_PREVIOUS optional, the secret before a rotation (valid 24 h)
//     CAPSULE_TIMESTAMP       value of the X-Capsule-Timestamp header
//     CAPSULE_SIGNATURE       value of X-Capsule-Signature
//     CAPSULE_SIGNATURE_PREVIOUS optional, value of X-Capsule-Signature-Previous
//     CAPSULE_NOW             optional unix seconds, for tests (default: now)
//   and the RAW request body on stdin (do not re-serialize the JSON).
//
// Exit code 0 = authentic and fresh, 1 = reject.
const crypto = require('node:crypto');

function verify({ secrets, timestamp, signatures, rawBody, now }) {
  const ts = Number(timestamp);
  if (!Number.isInteger(ts)) return false;
  if (Math.abs(now - ts) > 300) return false; // replay window
  let ok = false;
  for (const secret of secrets.filter(Boolean)) {
    const want = 'sha256=' + crypto.createHmac('sha256', secret).update(`${ts}.`).update(rawBody).digest('hex');
    for (const got of signatures.filter(Boolean)) {
      const a = Buffer.from(got.trim());
      const b = Buffer.from(want);
      // constant-time comparison; lengths are public
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) ok = true;
    }
  }
  return ok;
}

if (require.main === module) {
  const chunks = [];
  process.stdin.on('data', (c) => chunks.push(c));
  process.stdin.on('end', () => {
    const e = process.env;
    const ok = verify({
      secrets: [e.CAPSULE_SECRET, e.CAPSULE_SECRET_PREVIOUS],
      timestamp: e.CAPSULE_TIMESTAMP,
      signatures: [e.CAPSULE_SIGNATURE, e.CAPSULE_SIGNATURE_PREVIOUS],
      rawBody: Buffer.concat(chunks),
      now: e.CAPSULE_NOW ? Number(e.CAPSULE_NOW) : Math.floor(Date.now() / 1000),
    });
    process.exit(ok ? 0 : 1);
  });
}
module.exports = { verify };
