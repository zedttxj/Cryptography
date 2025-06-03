const { runAuthenticatedClient } = require('./clientCertRequester');

(async () => {
  const { certificate, privateKey } = await runAuthenticatedClient();
  console.log(certificate);
  console.log(privateKey);
})();
