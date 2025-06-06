# Step To Test
1. Run the relay first (`node relay-ws.js`)
2. Run both `roomtest.js` and `roomtest2.js`
3. Look for log like `[HubClient] Connected to <room_number>`
4. Extract the rooms' numbers and adjust the last 2 lines of the `CA.js`
5. Run `CA.js` (`node CA.js`)
7. Enjoy play

# How to apply it to your code

If your keys extraction look like this:  

```js
// const privateKey = fs.readFileSync(path.join(__dirname, './private.key'), 'utf-8');
// const publicKey = fs.readFileSync(path.join(__dirname, './room-public.pem'), 'utf-8');
```

Then you can replace it with this:

```js
const { runAuthenticatedClient, runAuthenticatedClient2Ways, requestCertificateFromHub } = require('/path/to/clientCertRequester'); // Adjust this path first
let privateKey, publicKey;

(async () => {
  const issued = await requestCertificateFromHub();
  const certificate = issued.certificate;
  privateKey = issued.privateKey;
  const caPublicKey = issued.caPublicKey;
  const roomId = issued.roomId;
  const result = await runAuthenticatedClient2Ways("ws://localhost:8888/hub", certificate, privateKey, caPublicKey, roomId);
  publicKey = result.clientPubKey;
  console.log(certificate);
  console.log(privateKey);
  console.log(publicKey);
})();
```

**Notice:** adjust the path to `clientCertRequester.js first`
If you only wanna keep the private key on 1 server and 1 public key on another server, in the last 2 lines in `CA.js`, you gotta place the room id of the server holding public key first. Additionally, replace `runAuthenticatedClient2Ways` with `runAuthenticatedClient`:
- On the server side that holds private key:
  ```js
  const { runAuthenticatedClient, runAuthenticatedClient2Ways, requestCertificateFromHub } = require('/path/to/clientCertRequester'); // Adjust this path first
  let privateKey;
  
  (async () => {
    const issued = await requestCertificateFromHub();
    const certificate = issued.certificate;
    privateKey = issued.privateKey;
    const caPublicKey = issued.caPublicKey;
    const roomId = issued.roomId;
    await runAuthenticatedClient("ws://localhost:8888/hub", certificate, privateKey, caPublicKey, roomId);
    console.log(certificate);
    console.log(privateKey);
  })();
  ```
- On the server side that holds public key:
  ```js
  const { runAuthenticatedClient, runAuthenticatedClient2Ways, requestCertificateFromHub } = require('/path/to/clientCertRequester'); // Adjust this path first
  let publicKey;
  
  (async () => {
    const issued = await requestCertificateFromHub();
    const certificate = issued.certificate;
    const privateKey = issued.privateKey;
    const caPublicKey = issued.caPublicKey;
    const roomId = issued.roomId;
    const result = await runAuthenticatedClient("ws://localhost:8888/hub", certificate, privateKey, caPublicKey, roomId);
    publicKey = result.clientPubKey;
    console.log(certificate);
    console.log(publicKey);
  })();
  ```
