'use strict';

const fs = require('fs');
const saml2 = require('saml2-js');
const meta = require.main.require('./src/meta');

let sp, idp;

async function configureSso() {
  if (sp && idp) return { sp, idp };

  const settings = await meta.settings.get('sso-saml');

  const spCert = readCert(settings.spCert);
  const spKey = readCert(settings.spKey);
  const idpCert = readCert(settings.idpCert);

  const spOptions = {
    entity_id: settings.spEntityId || 'http://localhost:4567',
    private_key: spKey,
    certificate: spCert,
    assert_endpoint: settings.assertEndpoint || 'http://localhost:4567/auth/saml/callback',
    force_authn: true,
    auth_context: {
      comparison: 'exact',
      class_refs: ['urn:oasis:names:tc:SAML:1.0:am:password'],
    },
    nameid_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    sign_get_request: true,
    allow_unencrypted_assertion: true,
  };

  const idpOptions = {
    sso_login_url: settings.idpLoginUrl,
    sso_logout_url: settings.idpLogoutUrl,
    certificates: [idpCert],
    force_authn: true,
    sign_get_request: true,
    allow_unencrypted_assertion: true,
  };

  sp = new saml2.ServiceProvider(spOptions);
  idp = new saml2.IdentityProvider(idpOptions);

  return { sp, idp };
}

function readCert(pathOrContent = '') {
  if (pathOrContent.trim().startsWith('-----BEGIN')) {
    return pathOrContent;
  }

  try {
    return fs.readFileSync(pathOrContent.trim(), 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read certificate from path: ${pathOrContent}`);
  }
}

async function generateLoginUrl() {
  const { sp, idp } = await configureSso();
  return new Promise((resolve, reject) => {
    sp.create_login_request_url(idp, {}, (err, loginUrl) => {
      if (err) return reject(err);
      resolve(loginUrl);
    });
  });
}

async function assertLogin(req) {
  const { sp, idp } = await configureSso();
  const body = req.body;

  return new Promise((resolve, reject) => {
    sp.post_assert(idp, { request_body: body }, (err, samlResponse) => {
      if (err) return reject(err);
      resolve(samlResponse);
    });
  });
}

async function generateLogoutUrl({ name_id, session_index }) {
  const { sp, idp } = await configureSso();
  return new Promise((resolve, reject) => {
    sp.create_logout_request_url(idp, { name_id, session_index }, (err, logoutUrl) => {
      if (err) return reject(err);
      resolve(logoutUrl);
    });
  });
}

module.exports = {
  generateLoginUrl,
  assertLogin,
  generateLogoutUrl,
  configureSso,
};
