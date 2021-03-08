// eslint-disable-next-line import/no-unresolved
import * as fs from 'fs';
import * as path from 'path';
import {
  HybridDecrypt,
  HybridEncrypt,
  pemPublicKeyToCryptoKey,
  encryptValue,
  encryptValues,
  getSealedSecret,
  getLabel,
} from '../index';

describe('index', () => {
  describe('encrypt and decrypt', () => {
    it('works', async () => {
      const publicKey = fs.readFileSync(path.join(__dirname, '../../public.pem'), 'utf8');
      const privateKey = fs.readFileSync(path.join(__dirname, '../../pk8.pem'));

      const pubKey = await pemPublicKeyToCryptoKey(publicKey);

      const privKey = await crypto.subtle.importKey('pkcs8', privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
        'encrypt',
        'decrypt',
      ]);

      const encryptedText = 'Bonjour le monde';
      const label = Buffer.from('label');

      const result = await HybridEncrypt(pubKey, encryptedText, label);

      const str = await HybridDecrypt(privKey, result, label);

      expect(str).toEqual(encryptedText);
    });
  });

  describe('import pem key', () => {
    it('works', async () => {
      const pemContent = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3OcM/3pefoIZjQLEM6RS
t47S0SA3KGIMnhh2hix/xQrmrYhN6oRXibdrmEPhhZhIN3vTf+sQ2PDYFDLy3VJQ
H5eU6leR/ehF00rBhGkS9iuBCCHZhX5WrPq+3YeSGLZlfDU11thEi5Mjntz7nyvz
oXQ/8XMYJWCzPiZ0dqWyqhbxXLJPixytxU1rdMUnqoHfuhvTyMVAGx7aCmCPUeNa
1pwl2O59M6fs1g/+oxA7GwoBSeue2cMJ9F1xpEKiLXWbDfhEyHAVSHanps3JLHe0
UVGUIiRfIpjOUv8I/9aOeScADy6oOTnY+U/6UKuIEhvlBtT9HicQUKVAoJrVtUgI
0thr/ZJLsPzwDJiwGjdLh5zPE2PTjyyzBDY5p/SIb2K4Y+ZSn3+DVzQuJxxUg1AF
X7uZDR62J/VpwgsP32RPNaeQ6OyHLG35oBKt07YO6dXql6R/TRPU1kmU89x1v9JZ
hLiLDcY1/+vdgwXj/wglImJQHn+9OFqKPOI8CM+IxMH46J7BVWh227SBsqo705Vn
GH0Jwi75wfj5arrXP/6fP1Yl137gMI/yt5WL4RlrdkzS6Pet1xv6agVW2cWFSOJu
yM62dL4W4XJNaBmDfMl/LGDwVJ+f+V/2yfF89SrAHgn0lwLwowGdzH0A8MW7BFEV
UAHog3BetRu+fy6v2QZu+IcCAwEAAQ==
-----END PUBLIC KEY-----
`;

      const key = await pemPublicKeyToCryptoKey(pemContent);
      expect(key).toBeDefined();
      const encrypted = await HybridEncrypt(key, 'hello', Buffer.from(''));
      expect(encrypted).toBeDefined();
    });
  });

  describe('encryptValue', () => {
    it('should encryptValue', async () => {
      const pemContent = `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----

`;

      const encrypted = await encryptValue({
        pemKey: pemContent,
        name: 'some-name',
        namespace: 'some-namespace',
        scope: 'strict',
        value: 'hello',
      });

      expect(encrypted).toBeDefined();
    });
  });

  describe('encryptValues', () => {
    it('should encryptValues', async () => {
      const pemContent = `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----

`;

      const encrypted = await encryptValues({
        pemKey: pemContent,
        name: 'some-name',
        namespace: 'some-namespace',
        scope: 'strict',
        values: {
          value1: 'hello',
          value2: 'world',
        },
      });

      // @ts-expect-error
      expect(encrypted.value1).toBeDefined();
      // @ts-expect-error
      expect(encrypted.value2).toBeDefined();
    });
  });

  describe('getLabel', () => {
    it("should set label to '' for scope=cluster", () => {
      expect(getLabel({ scope: 'cluster', namespace: 'namespace', name: 'name' })).toEqual('');
    });
    it("should set label to 'namespace' for scope=namespace", () => {
      expect(getLabel({ scope: 'namespace', namespace: 'namespace', name: 'name' })).toEqual('namespace');
    });
    it("should set label to 'namespace/name' for scope=strict", () => {
      expect(getLabel({ scope: 'strict', namespace: 'namespace', name: 'name' })).toEqual('namespace/name');
    });
  });

  describe('getSealedSecret', () => {
    it('should getSealedSecret for scope=strict', async () => {
      const pemContent = `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----

`;

      const secret = await getSealedSecret({
        pemKey: pemContent,
        name: 'some-name',
        namespace: 'some-namespace',
        scope: 'strict',
        values: {
          value1: 'hello',
          value2: 'world',
        },
      });

      expect(secret).toMatchSnapshot({
        spec: {
          encryptedData: {
            value1: expect.any(String),
            value2: expect.any(String),
          },
        },
      });
    });

    it('should getSealedSecret for scope=namespace', async () => {
      const pemContent = `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----

`;

      const secret = await getSealedSecret({
        pemKey: pemContent,
        name: 'some-name',
        namespace: 'some-namespace',
        scope: 'namespace',
        values: {
          value1: 'hello',
          value2: 'world',
        },
      });

      expect(secret).toMatchSnapshot({
        spec: {
          encryptedData: {
            value1: expect.any(String),
            value2: expect.any(String),
          },
        },
      });
    });

    it('should getSealedSecret for scope=cluster', async () => {
      const pemContent = `-----BEGIN CERTIFICATE-----
MIIErjCCApagAwIBAgIRAOqAV9ZpCl1cwMunTHirqXwwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMDA1MjYwODQxMTBaFw0zMDA1MjQwODQxMTBaMAAwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDc5wz/el5+ghmNAsQzpFK3jtLRIDcoYgyeGHaG
LH/FCuatiE3qhFeJt2uYQ+GFmEg3e9N/6xDY8NgUMvLdUlAfl5TqV5H96EXTSsGE
aRL2K4EIIdmFflas+r7dh5IYtmV8NTXW2ESLkyOe3PufK/OhdD/xcxglYLM+JnR2
pbKqFvFcsk+LHK3FTWt0xSeqgd+6G9PIxUAbHtoKYI9R41rWnCXY7n0zp+zWD/6j
EDsbCgFJ657Zwwn0XXGkQqItdZsN+ETIcBVIdqemzcksd7RRUZQiJF8imM5S/wj/
1o55JwAPLqg5Odj5T/pQq4gSG+UG1P0eJxBQpUCgmtW1SAjS2Gv9kkuw/PAMmLAa
N0uHnM8TY9OPLLMENjmn9IhvYrhj5lKff4NXNC4nHFSDUAVfu5kNHrYn9WnCCw/f
ZE81p5Do7IcsbfmgEq3Ttg7p1eqXpH9NE9TWSZTz3HW/0lmEuIsNxjX/692DBeP/
CCUiYlAef704Woo84jwIz4jEwfjonsFVaHbbtIGyqjvTlWcYfQnCLvnB+Plqutc/
/p8/ViXXfuAwj/K3lYvhGWt2TNLo963XG/pqBVbZxYVI4m7IzrZ0vhbhck1oGYN8
yX8sYPBUn5/5X/bJ8Xz1KsAeCfSXAvCjAZ3MfQDwxbsEURVQAeiDcF61G75/Lq/Z
Bm74hwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAAEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAgEAKLvQtDV5QVNUEcg3ywL03IwtNWmU8EqqASgckVAc
dmeGnFwV7+7VnrIHI34xCZDhAVEnlMAb0oELgTDSstTx4p25rjqOLQfPcb0TsPko
cpJHS00trLsLX4DYoZ1dLprgySGrC9jQ/FMYMK1oZ0M04gA/U9alNVNu2DWKosHu
JGRYBbXVnse5rZi3hl4GV5Vq2ZR/3GHL9xgcjMcSLqHhXoSULLm5qEBUA5flV0BJ
bY2FEfpm1NHSh5vOaA5t7lrW/XqiAuo8lJM2Ztg/dsX6Zxq7Memq8nqMRpoMFbdj
i0jTxlPL1ssVHvvmWcLsdx9fHX7XaNGZ4ulA6BIL4DZQMPxvtFk9alqbc9WnjsqL
/8QA3STXkTSzWrSsTUcabxlp5+MLHRf31iE1dlGVv7FVLjPy29T145eSzoNPM9sN
1+aBLnXDCj5HUwto8+iKJn7VTURty5KceUFSeURXM2IKYYTec8MElLX0PeXi+SvO
W37ZCn0RMnljus5aTUPbRHNvJ3Ut/1WDLQu8X0wIm509F1A80Udg5FTxHasBizM2
L+rpr2923MG1JSitDfvNj1rxx1FLdynP84SOEJDCtbB8YRcDUC4bHKrAcG4FBAFX
UDzbbsoR58onjcZW3QH4mvV9K3+llwHSo8zfYyKRhF8pUUJHp7A/8DgMYQyYAv2z
bag=
-----END CERTIFICATE-----

`;

      const secret = await getSealedSecret({
        pemKey: pemContent,
        name: 'some-name',
        namespace: 'some-namespace',
        scope: 'cluster',
        values: {
          value1: 'hello',
          value2: 'world',
        },
      });

      expect(secret).toMatchSnapshot({
        spec: {
          encryptedData: {
            value1: expect.any(String),
            value2: expect.any(String),
          },
        },
      });
    });
  });
});
