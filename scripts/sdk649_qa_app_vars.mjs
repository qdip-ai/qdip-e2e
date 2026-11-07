/**
 * SDK #649: repository-variable wiring preflight, not an authorization proof.
 * No environment values are printed or sent to any external endpoint.
 */
import assert from 'node:assert/strict';

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
