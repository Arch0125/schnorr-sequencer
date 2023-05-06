const axios = require('axios');
const { ec } = require('elliptic');
const BN = require('bn.js');
const sha256 = require('js-sha256').sha256;

const curve = new ec('secp256k1');
const user = curve.genKeyPair();
const Pu = user.getPublic();

let tx = {
    from: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    to: '0x832daF8dD2fE8F7bC3Df5F05b5e5A8a5aF22A160',
    value: '1000000000000000000', // 1 Ether in wei
    gas: 21000,
    gasPrice: '20000000000', // 20 Gwei in wei
    nonce: 0,
    data: '0x' // No input data in this example
};

tx = JSON.stringify(tx);

const m = sha256(tx);

const ru = curve.genKeyPair();
const Ru = ru.getPublic();

(async () => {
  try {
    const { data: { i, Rs, e } } = await axios.post('http://localhost:3000/register', { Ru: Ru.encode('hex'), Pu: Pu.encode('hex'), m });
    const eBN = new BN(e, 16);

    const RsPub = curve.keyFromPublic(Rs, 'hex').getPublic();

    const su = ru.priv.add(user.priv.mul(eBN)).mod(curve.n);

    // Continue the protocol with the sequencer using su and other required data
    console.log('User partial signature (su):', su.toString(16));

    const { data: { isValid } } = await axios.post('http://localhost:3000/verify', { su: su.toString(16), Ru: Ru.encode('hex'), Pu: Pu.encode('hex'), e });
    console.log('Is the signature valid?', isValid);

  } catch (error) {
    console.error('Error during communication with the sequencer:', error.message);
  }
})();
