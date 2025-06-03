const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

const caPublicKey = fs.readFileSync('public.pem');

function hashMessageWithoutJWT(msg) {
  const copy = { ...msg };
  delete copy.jwt;
  return crypto.createHash('sha256')
    .update(JSON.stringify(copy))
    .digest('hex');
}

function verifyFromCA(jwtToken, msgWithoutVerification) {
  try {
    const decoded = jwt.verify(jwtToken, caPublicKey, {
      algorithm: 'RS256'
    });

    const localHash = hashMessageWithoutJWT(msgWithoutVerification);

    if (decoded.messageHash !== localHash) {
      throw new Error("Message hash mismatch");
    }

    return true;
  } catch (err) {
    console.error("❌ JWT verification failed:", err.message);
    return false;
  }
}

module.exports = { verifyFromCA };
