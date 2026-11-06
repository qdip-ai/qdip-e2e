/**
 * SDK #649: repository-variable wiring preflight, not an authorization proof.
 * No environment values are printed or sent to any external endpoint.
 */
import assert from 'node:assert/strict';
import { publicEncrypt, constants as cryptoConstants } from 'node:crypto';

const REQUIRED = [
  'QDIP_SDK_QA_PROJECT_ID',
  'QDIP_SDK_MANAGED_APP_ID',
  'QDIP_SDK_MANAGED_CLIENT_ID',
  'QDIP_SDK_EXTERNAL_APP_ID',
  'QDIP_SDK_EXTERNAL_CLIENT_ID',
];

export function validateQaApplicationVariables(env) {
  for (const key of REQUIRED) {
    if (typeof env[key] !== 'string' || !env[key].trim()) {
      throw new Error('MISSING_' + key);
    }
  }
  for (const key of ['QDIP_SDK_QA_PROJECT_ID', 'QDIP_SDK_MANAGED_APP_ID', 'QDIP_SDK_EXTERNAL_APP_ID']) {
    if (!/^[0-9]{1,32}$/.test(env[key])) {
      throw new Error('INVALID_' + key);
    }
  }
  for (const key of ['QDIP_SDK_MANAGED_CLIENT_ID', 'QDIP_SDK_EXTERNAL_CLIENT_ID']) {
    if (!/^[^\s\x00-\x1f\x7f]{1,256}$/u.test(env[key])) {
      throw new Error('INVALID_' + key);
    }
  }
  if (env.QDIP_SDK_MANAGED_APP_ID === env.QDIP_SDK_EXTERNAL_APP_ID) {
    throw new Error('DUPLICATE_APPLICATION_ID');
  }
  if (env.QDIP_SDK_MANAGED_CLIENT_ID === env.QDIP_SDK_EXTERNAL_CLIENT_ID) {
    throw new Error('DUPLICATE_OIDC_CLIENT_ID');
  }
}


const SDK_QA_OPERATOR_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwTFB56fmk0s2AI8RigI
QA6e9uZ/sZIiWUV1lltOQzGGxwYnmgJqoCd12l2aeR5Lt1WBojrhWyc4mT9PaCjb
Jx/34z/IKBgH5/sf1GSTo2FW9Wy1JQYIcYkhIMcZ0yZ/dyuYIfgMWZurOD3sjkYN
keu1DeVjiGBAHnM9i0jnREnBw3JmE0UM6ub+sejEW1Qwmc9lSq1QZV1cvy8UM7Fo
2VSEpvhSGxR0G60rUgwyt0ZK6HhzX8jvGFi8+Czy5+OaRj0YCk8RH8VLQERpPJUC
CN/M0x4HqJGzwQZD6BAgyhWHkHmbJidPtuwLYScxTsN32kidzX1pevqLQCGgU+0r
mwIDAQAB
-----END PUBLIC KEY-----`;

// One-time operator diagnostic for SDK staging only. The QA client's OAuth
// public IDs are never emitted in plaintext or persisted in a repository.
// Ciphertexts can be opened only by the operator's ephemeral private key.
function sealedQaClientId(value) {
  const bytes = Buffer.from(value, 'utf8');
  const pieces = [];
  for (let i = 0; i < bytes.length; i += 100) {
    pieces.push(publicEncrypt({
      key: SDK_QA_OPERATOR_PUBLIC_KEY,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, bytes.subarray(i, i + 100)).toString('base64url'));
  }
  return pieces.join('.');
}

function selfTest() {
  const fixture = {
    QDIP_SDK_QA_PROJECT_ID: '111111111111111111',
    QDIP_SDK_MANAGED_APP_ID: '222222222222222222',
    QDIP_SDK_MANAGED_CLIENT_ID: 'managed@qa',
    QDIP_SDK_EXTERNAL_APP_ID: '333333333333333333',
    QDIP_SDK_EXTERNAL_CLIENT_ID: 'external@qa',
  };
  assert.doesNotThrow(() => validateQaApplicationVariables(fixture));
  for (const key of REQUIRED) {
    assert.throws(() => validateQaApplicationVariables({ ...fixture, [key]: '' }),
      new RegExp('^Error: MISSING_' + key + '$'));
  }
  assert.throws(() => validateQaApplicationVariables({ ...fixture, QDIP_SDK_QA_PROJECT_ID: 'wrong' }),
    /INVALID_QDIP_SDK_QA_PROJECT_ID/);
  assert.throws(() => validateQaApplicationVariables({ ...fixture, QDIP_SDK_MANAGED_APP_ID: fixture.QDIP_SDK_EXTERNAL_APP_ID }),
    /DUPLICATE_APPLICATION_ID/);
  assert.throws(() => validateQaApplicationVariables({ ...fixture, QDIP_SDK_MANAGED_CLIENT_ID: fixture.QDIP_SDK_EXTERNAL_CLIENT_ID }),
    /DUPLICATE_OIDC_CLIENT_ID/);
  assert.throws(() => validateQaApplicationVariables({ ...fixture, QDIP_SDK_EXTERNAL_CLIENT_ID: 'has space' }),
    /INVALID_QDIP_SDK_EXTERNAL_CLIENT_ID/);
  console.log('SDK649_QA_VARIABLES_NEGATIVE_REGRESSION=PASS');
}

if (process.argv[1]?.endsWith('sdk649_qa_app_vars.mjs')) {
  if (process.argv[2] === '--self-test') {
    selfTest();
  } else {
    try {
      validateQaApplicationVariables(process.env);
      console.log('SDK649_QA_APPLICATION_VARIABLES=PASS_REFERENCE_SHAPE_ONLY');
      console.log('SDK649_QA_MANAGED_CLIENT_CIPHERTEXT=' +
        sealedQaClientId(process.env.QDIP_SDK_MANAGED_CLIENT_ID));
      console.log('SDK649_QA_EXTERNAL_CLIENT_CIPHERTEXT=' +
        sealedQaClientId(process.env.QDIP_SDK_EXTERNAL_CLIENT_ID));
      console.log('SDK649_QA_PROJECT_OWNER=NOT_VERIFIED');
      console.log('SDK649_QA_CANONICAL_APP_BINDINGS=NOT_VERIFIED');
      console.log('SDK649_QA_HTTP_WSS_E2E=NOT_RUN');
    } catch (error) {
      const code = error instanceof Error && /^[A-Z0-9_]{4,100}$/.test(error.message)
        ? error.message : 'SANITIZED_ERROR';
      console.error('SDK649_QA_APPLICATION_VARIABLES=FAIL_' + code);
      process.exitCode = 1;
    }
  }
}
