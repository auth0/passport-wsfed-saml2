var assert = require('assert'),
    fs = require('fs'),
    utils = require('./utils'),
    moment = require('moment'),
    should = require('should'),
    saml20 = require('saml').Saml20,
    SamlPassport = require('../lib/passport-wsfed-saml2/saml').SAML;

describe('saml 2.0 assertion', function () {

  it('should parse attributes', function (done) {
    // cert created with:
    // openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/CN=auth0.auth0.com/O=Auth0 LLC/C=US/ST=Washington/L=Redmond' -keyout auth0.key -out auth0.pem

    var options = {
      cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
      key: fs.readFileSync(__dirname + '/test-auth0.key'),
      issuer: 'urn:issuer',
      lifetimeInSeconds: 600,
      audiences: 'urn:myapp',
      attributes: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
      },
      nameIdentifier:       'foo',
      nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    };

    var signedAssertion = saml20.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp'});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {

      assert.ok(profile);
      assert.equal('foo', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']);
      assert.equal('Foo Bar', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']);
      assert.equal('foo@bar.com', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
      assert.equal('foo@bar.com', profile['email']);
      assert.equal('urn:issuer', profile['issuer']);
      done();
    });

  });
});
