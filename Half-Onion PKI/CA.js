const jwt = require('jsonwebtoken');
var fs = require('fs');
// const crypto = require('crypto');
const relaykey = fs.readFileSync('private.key');
function hash(obj) {
  return require('crypto')
    .createHash('sha256')
    .update(JSON.stringify(obj))
    .digest('hex');
}
function signAsCA(msg) {
  const copy = { ...msg };
  // delete copy.jwt; // 🔑 must match verification logic

  const payload = {
    messageHash: hash(copy), // consistent with relay
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 30,
    issuer: 'noveltellers-CA'
  };

  return jwt.sign(payload, relaykey, {
    algorithm: 'RS256'
  });
}

const { generateKeyPairSync, createSign, createVerify, createPublicKey } = require('crypto');

// Generate CA key pair
const { publicKey: caPubKey, privateKey: caPrivKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const caPubKeyPem = caPubKey.export({ type: 'spki', format: 'pem' });

// Signs cert (not just the key)
function signCert(certData) {
  const signer = createSign('sha256');
  signer.update(JSON.stringify(certData));
  signer.end();
  return signer.sign(caPrivKey, 'base64');
}

// Verifies that the client owns its public key
function verifyClientKeys(publicKeyPem, signature) {
  const verifier = createVerify('sha256');
  verifier.update(publicKeyPem);
  verifier.end();

  const pubKeyObj = createPublicKey(publicKeyPem);
  return verifier.verify(pubKeyObj, signature, 'base64');
}

const challengroom = Math.random().toString(36).substring(2, 10);
function signingCert(room) {
  const WebSocket = require("ws");

  const ws = new WebSocket(`ws://localhost:8888/hub/${room}`);
  ws.on("open", () => {
    console.log("Connected to room");
    ws.send(JSON.stringify({ type: "hello", clientId: "node-client-1" }));
  });

  ws.on("message", (data) => {
    try {
      const parsed = JSON.parse(data.toString());
      console.log("Received:", parsed);
      let msg;

      if (parsed.type === "init-connection" && parsed.peerCount === 1) {
        msg = { type: "talk", clientId: "node-client-1" };
      }

      if (
        parsed.type === "csr" &&
        parsed.peerlength === 2 &&
        verifyClientKeys(parsed.publicKey, parsed.signature)
      ) {
        // Build cert content
        const cert = {
          publicKey: parsed.publicKey,
          issuedAt: Date.now(),
          expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
          issuedBy: "noveltellers-CA",
        };

        const signedCert = {
          ...cert,
          certSignature: signCert(cert),
          caPublicKey: caPubKeyPem,
          clientId: "node-client-1"
        };

        msg = {
          type: "key-signed",
          certificate: signedCert,
          roomId: challengroom
        };
        
        const token = signAsCA(msg);
        ws.send(JSON.stringify({
          ...msg,
          jwt: token
        }));
        ws.close();
        return;
      }
      const token = signAsCA(msg);
      ws.send(JSON.stringify({
        ...msg,
        jwt: token
      }));
    } catch (err) {
      console.error("Invalid message:", err.message);
    }
  });

  ws.on("close", () => {
    console.log("Disconnected");
  });
}

signingCert("2sbe13ph");
signingCert("9vzsm4j2");
