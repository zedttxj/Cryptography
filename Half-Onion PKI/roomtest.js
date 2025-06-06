const { runAuthenticatedClient, runAuthenticatedClient2Ways, requestCertificateFromHub } = require('./clientCertRequester');

(async () => {
  const { certificate, privateKey, caPublicKey, roomId } = await requestCertificateFromHub();
  const { clientPubKey: publicKey} = await runAuthenticatedClient2Ways("ws://localhost:8888/hub", certificate, privateKey, caPublicKey, roomId);
  console.log(certificate);
  console.log(privateKey);
  console.log(publicKey);
})();

// The same thing for roomtest2.js
