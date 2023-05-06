// sequencer.js

const express = require("express");
const { ec } = require("elliptic");
const BN = require("bn.js");
const sha256 = require("js-sha256").sha256;

const curve = new ec("secp256k1");
const sequencer = curve.genKeyPair();
const Ps = sequencer.getPublic();

const app = express();
app.use(express.json());

app.post("/register", (req, res) => {
  const { Ru, Pu, m } = req.body;

  const i = "index value";
  const rs = curve.genKeyPair();
  const Rs = rs.getPublic();

  const userPub = curve.keyFromPublic(Pu, "hex");
  const X = userPub.getPublic().mul(1);

  const userNonce = curve.keyFromPublic(Ru, "hex");
  const R = userNonce.getPublic().add(Rs);

  const e = sha256(
    Buffer.concat([
      Buffer.from(R.encode(true)),
      Buffer.from(X.encode(true)),
      Buffer.from(m, "hex"),
      Buffer.from(i),
    ])
  );
  const eBN = new BN(e, 16);

  res.json({ i, Rs: Rs.encode("hex"), e });
});

app.post("/verify", (req, res) => {
  const { su, Ru, Pu, e } = req.body;
  const userPub = curve.keyFromPublic(Pu, 'hex');
  const userNonce = curve.keyFromPublic(Ru, 'hex');
    const eBN = new BN(e, 16);
  const isValid = curve.g.mul(new BN(su, 16)).eq(userNonce.getPublic().add(userPub.getPublic().mul(eBN).mul(1)));
  if(isValid) {
    const sequencer = curve.genKeyPair();
    const rs = curve.genKeyPair();
    const Rs = rs.getPublic();
    const rsp = rs.getPrivate();
    const ss = rs.priv.add(sequencer.priv.mul(eBN)).mod(curve.n)
    const s = new BN(su, 16).add(ss).mod(curve.n);
    const R = userNonce.getPublic().add(Rs);
    const sHex = s.toString(16);
    const RHex = R.encode('hex');
    const signatureHash = sha256(Buffer.concat([Buffer.from(RHex, 'hex'), Buffer.from(sHex, 'hex')]));
    console.log('Signature hash:', signatureHash);
  }
  res.json({ isValid: isValid });
});

app.listen(3000, () => {
  console.log("Sequencer listening on port 3000");
});
