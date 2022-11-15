# AES-GCM + RSA OAEP encryption <a href="https://www.npmjs.com/package/@socialgouv/aes-gcm-rsa-oaep"><img src="https://img.shields.io/npm/v/@socialgouv/aes-gcm-rsa-oaep.svg" alt="Npm version"></a> 


AES-GCM + RSA-OAEP encryption/decryption using WebCrypto API in NodeJS or in the browser

Tests uses `@peculiar/webcrypto` for polyfilling browser crypto api.

This can be used to replace [kubeseal](https://github.com/bitnami-labs/sealed-secrets) encryption in JavaScript environments.

See demo : http://socialgouv.github.io/webseal

## Usage

### High level

```js
import { encryptValue, encryptValues, getSealedSecret } from "@socialgouv/aes-gcm-rsa-oaep"

// encrypt single value
const encryptedValue =  encryptValue({
  pemKey: "somekey",
  scope: "cluster",
  namespace: "dev",
  name: "my-secret",
  value: "plain-value";
});

// encrypt multiple values
const encryptedValue =  encryptValues({
  pemKey: "somekey",
  scope: "cluster",
  namespace: "dev",
  name: "my-secret",
  values: {
    value1: "plain1",
    value2: "plain2"
  }
});

// get sealed-secret
const sealedSecret =  getSealedSecret({
  pemKey: "somekey",
  scope: "cluster",
  namespace: "dev",
  name: "my-secret",
  values: {
    value1: "plain1",
    value2: "plain2"
  }
});
```

## Low level

```js
import { pki } from 'node-forge';
import { HybridEncrypt, pemPublicKeyToCryptoKey } from '@socialgouv/aes-gcm-rsa-oaep';

const publicKeyPem = pki.publicKeyToPem(cert.publicKey);
const publicKey = await pemPublicKeyToCryptoKey(publicKeyPem);

const plainText = 'Bonjour le monde';
const label = Buffer.from('');

const result = await HybridEncrypt(publicKey, plainText, label);

const sealedText = Buffer.from(result).toString('base64');
```

## Encryption Algorithm

To encrypt content, we go through the following steps :

-   Generate a 128 bits AES key

-   Encrypt the payload using the AES-GCM algorithm (with the previously generated key). We use a 12 bits of 0 as IV, because the key is only used once.

-   Encrypt the AES key using the RSA-OAEP algorithm (using the provided public key).

-   Generate the output payload this way :
  (RSA payload length as 2 bytes integer) || (RSA encrypted aes key) || (AES encrypted payload)
