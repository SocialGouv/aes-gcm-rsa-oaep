import { pki } from 'node-forge';

// Utility functions come from here : https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
import { str2ab } from './utils';

type Scope = 'cluster' | 'namespace' | 'strict';

type GetLabelParams = {
  scope: Scope;
  namespace: string;
  name: string;
};

type EncryptValueParams = {
  pemKey: string;
  scope: Scope;
  namespace: string;
  name: string;
  value: string;
};

type EncryptParams = {
  publicKey: CryptoKey;
  value: string;
  label: Buffer;
};

type EncryptValuesParams = {
  pemKey: string;
  scope: Scope;
  namespace: string;
  name: string;
  values: Record<string, any>;
};

type GetSealedSecretParams = {
  pemKey: string;
  scope: Scope;
  namespace: string;
  name: string;
  values: Record<string, any>;
};

const crypto = typeof window !== 'undefined' && window.crypto ? window.crypto : require('crypto').webcrypto;

// Recommended nonce size for AES GCM is 96 bits
const AES_GCM_NONCE_SIZE = 12;

/**
 * Converts an ArrayBuffer to a string
 * @param buf
 */
function ab2str(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf);
}

function numberToLEBuffer(num: number): ArrayBuffer {
  const firstNumber = num / 256;
  const secondNumber = num % 256;
  return new Uint8Array([firstNumber, secondNumber]);
}

function numberFromLEBuffer(buffer: ArrayBuffer): number {
  const intArray = new Uint8Array(buffer.slice(0, 2));
  return intArray[0] * 256 + intArray[1];
}

/**
 * Encrypts a string using AES-GCM algorithm with a 0 nonce
 * @param key
 * @param str
 */
const aesGcmEncrypt = async (key: CryptoKey, str: string): Promise<ArrayBuffer> => {
  const nonce = new Uint8Array(AES_GCM_NONCE_SIZE);
  nonce.fill(0);
  return crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    str2ab(str)
  );
};

/**
 * Decrypts an array buffer using AES-GCM algorithm with a 0 nonce
 * @param key
 * @param enc
 */
const aesGcmDecrypt = async (key: CryptoKey, enc: ArrayBuffer): Promise<string> => {
  const nonce = new Uint8Array(AES_GCM_NONCE_SIZE);
  nonce.fill(0);
  const result = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    enc
  );

  return ab2str(result);
};

const sessionKeyLength = 256;

/**
 * Encrypts a string with AES-GCM/RSA-OAEP
 * @param pubKey - The RSA public key
 * @param text - The text to encrypt
 * @param label - The OAEP label
 * @constructor
 */
export async function HybridEncrypt(pubKey: CryptoKey, text: string, label: ArrayBuffer): Promise<ArrayBuffer> {
  const sessionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: sessionKeyLength }, true, ['encrypt']);

  const rawSessionKey = await crypto.subtle.exportKey('raw', sessionKey);

  const rsaCipherText = await crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
      label,
    },
    pubKey,
    rawSessionKey
  );

  const rsaCipherLength = numberToLEBuffer(rsaCipherText.byteLength);
  const result = await aesGcmEncrypt(sessionKey, text);

  const resultBuffer = new Uint8Array(rsaCipherLength.byteLength + rsaCipherText.byteLength + result.byteLength);

  resultBuffer.set(new Uint8Array(rsaCipherLength), 0);
  resultBuffer.set(new Uint8Array(rsaCipherText), rsaCipherLength.byteLength);
  resultBuffer.set(new Uint8Array(result), rsaCipherLength.byteLength + rsaCipherText.byteLength);
  return resultBuffer.buffer;
}

/**
 * Decrypts a string with AES-GCM/RSA-OAEP
 * @param privKey - The RSA private key
 * @param cipherText - The encrypted text
 * @param label - The OAEP label
 * @constructor
 */
export async function HybridDecrypt(privKey: CryptoKey, cipherText: ArrayBuffer, label: ArrayBuffer): Promise<string> {
  const rsaLength = numberFromLEBuffer(cipherText.slice(0, 2));
  const rsaCipherText = new Uint8Array(cipherText.slice(2, 2 + rsaLength));
  const aesCipherText = new Uint8Array(cipherText.slice(2 + rsaLength));
  const sessionKey = await crypto.subtle.decrypt(
    {
      name: 'RSA-OAEP',
      label,
    },
    privKey,
    rsaCipherText
  );

  const key = await crypto.subtle.importKey('raw', sessionKey, { name: 'AES-GCM', length: sessionKeyLength }, false, [
    'decrypt',
  ]);

  return aesGcmDecrypt(key, aesCipherText);
}

function uint8Str2Ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i += 1) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

const atob =
  typeof window !== 'undefined'
    ? window.atob
    : function (str: string) {
        return Buffer.from(str, 'base64').toString('binary');
      };

export async function pemPublicKeyToCryptoKey(pemContent: string): Promise<CryptoKey> {
  const data = pemContent
    .replace(/-*BEGIN PUBLIC KEY-*/, '')
    .replace(/-*END PUBLIC KEY-*/, '')
    .replace(/\n/g, '');

  const keyBuffer = uint8Str2Ab(atob(data));

  return crypto.subtle.importKey('spki', keyBuffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}

const getLabel = ({ scope, namespace, name }: GetLabelParams): string => {
  if (scope === 'cluster') {
    return '';
  }
  if (scope === 'namespace') {
    return namespace;
  }
  return `${namespace}/${name}`;
};

const getPublicKey = async (pemKey: string): Promise<CryptoKey> => {
  const cert = pki.certificateFromPem(pemKey);
  const publicKeyPem = pki.publicKeyToPem(cert.publicKey);
  const publicKey = await pemPublicKeyToCryptoKey(publicKeyPem);
  return publicKey;
};

export const encryptFromPublicKey = async (args: EncryptParams) =>
  Buffer.from(await HybridEncrypt(args.publicKey, args.value, args.label)).toString('base64');

export const encryptValue = async (args: EncryptValueParams): Promise<string> => {
  const publicKey = await getPublicKey(args.pemKey);
  const label = Buffer.from(getLabel({ scope: args.scope, namespace: args.namespace, name: args.name }));
  const result = await encryptFromPublicKey({ publicKey, label, value: args.value });

  HybridEncrypt(publicKey, args.value, label);
  return Buffer.from(result).toString('base64');
};

export const encryptValues = async (args: EncryptValuesParams) => {
  const publicKey = await getPublicKey(args.pemKey);
  const label = Buffer.from(getLabel({ scope: args.scope, namespace: args.namespace, name: args.name }));
  const encryptedValues = (
    await Promise.all(
      Object.keys(args.values).map(async (key) => ({
        key,
        value: await encryptFromPublicKey({ publicKey, value: args.values[key], label }),
      }))
    )
  ).reduce((a, c) => ({ ...a, [c.key]: c.value }), {});
  return encryptedValues;
};

export const getSealedSecret = async (args: GetSealedSecretParams) => {
  const encryptedData = await encryptValues(args);

  const annotations = {} as Record<string, string>;
  if (args.scope === 'cluster') {
    annotations['sealedsecrets.bitnami.com/cluster-wide'] = 'true';
  } else if (args.scope === 'namespace') {
    annotations['sealedsecrets.bitnami.com/namespace-wide'] = 'true';
  }

  const manifest = {
    apiVersion: 'bitnami.com/v1alpha1',
    kind: 'SealedSecret',
    metadata: {
      annotations,
      name: args.name,
      namespace: args.namespace,
    },
    spec: {
      encryptedData,
    },
    template: {
      metadata: {
        annotations,
        name: args.name,
      },
      type: 'Opaque',
    },
  };

  return manifest;
};
