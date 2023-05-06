const { ec } = require('elliptic');
const BN = require('bn.js');
const sha256 = require('js-sha256').sha256;

const curve = new ec('secp256k1');

// Sequencer and user key generation
const sequencer = curve.genKeyPair();
const user = curve.genKeyPair();

// Sequencer registers public key and stakes ETH
const Ps = sequencer.getPublic();

// User generates transaction and calculates hash, public key, and public nonce
let tx = {
  from: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
  to: '0x832daF8dD2fE8F7bC3Df5F05b5e5A8a5aF22A160',
  value: '1000000000000000000', // 1 Ether in wei
  gas: 21000,
  gasPrice: '20000000000', // 20 Gwei in wei
  nonce: 0,
  data: '' // No input data in this example
}
tx = JSON.stringify(tx);
const m = sha256(tx);
const Pu = user.getPublic();
const ru = curve.genKeyPair();
const Ru = ru.getPublic();

// User sends Ru, Pu, and m to the sequencer
// Sequencer secures an index and generates a random nonce
const i = '1';
const rs = curve.genKeyPair();
const Rs = rs.getPublic();

// Sequencer calculates the challenge value e and sends Rs and i back to the user
const wu = 1;
const ws = 1;
const X = user.getPublic().mul(new BN(wu)).add(sequencer.getPublic().mul(new BN(ws)));
const R = Ru.add(Rs);
const e = sha256(Buffer.concat([Buffer.from(R.encode(true)), Buffer.from(X.encode(true)), Buffer.from(m, 'hex'), Buffer.from(i)]));
const eBN = new BN(e, 16); // Convert e to a Big Number

// User calculates their partial signature su and sends it to the sequencer along with the transaction data
const su = ru.priv.add(user.priv.mul(eBN)).mod(curve.n);
const signatureData = { su: su, tx: tx };

// Sequencer verifies the signature and transaction hash
const isValid = curve.g.mul(su).eq(Ru.add(Pu.mul(eBN)));
const isValidHash = sha256(tx) === m;

if (isValid && isValidHash) {
  // Sequencer calculates their partial signature ss and sends it back to the user
  const ss = rs.priv.add(sequencer.priv.mul(eBN)).mod(curve.n);

  // Both parties can now create the full signature (s, R) and publish it
  const s = su.add(ss).mod(curve.n);
  const fullSignature = { s: s, R: R };
  const sHex = s.toString(16);
  const RHex = R.encode('hex');
  const signatureHash = sha256(sHex + RHex);
  // Verify the signature using the combined public key X and other known values
  const lhs = curve.g.mul(s);
  const rhs = R.add(X.mul(eBN));
  const isSignatureValid = lhs.eq(rhs);

  if (isSignatureValid) {
    console.log(`Signature is valid. Signature hash: 0x${signatureHash}`);
  } else {
    console.log('Signature is invalid.');
  }
} else {
  console.log('Invalid signature or transaction hash.');
}