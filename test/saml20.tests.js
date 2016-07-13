var assert = require('assert'),
    fs = require('fs'),
    utils = require('./utils'),
    moment = require('moment'),
    should = require('should'),
    saml20 = require('saml').Saml20,
    SamlPassport = require('../lib/passport-wsfed-saml2/saml').SAML;

describe('saml 2.0 assertion', function () {
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

  it('should parse attributes', function (done) {

    var signedAssertion = saml20.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(err, profile) {
      if (err) return done(err);

      assert.ok(profile);
      assert.equal('foo', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']);
      assert.equal('Foo Bar', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']);
      assert.equal('foo@bar.com', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
      assert.equal('foo@bar.com', profile['email']);
      assert.equal('urn:issuer', profile['issuer']);
      done();
    });

  });

  it('should parse attributes with multiple values', function (done) {

    options.attributes = {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': ['Admins', 'Contributors']
    };

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(err, profile) {
      if (err) return done(err);

      assert.ok(profile);
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.be.an.instanceOf(Array);
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.include('Admins');
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.include('Contributors');
      done();
    });

  });

  it('should validate expiration', function (done) {

    options.lifetimeInSeconds = -10000;

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.exists(err);
      err.message.should.equal('assertion has expired.');
      should.not.exists(profile);
      
      done();
    });

  });

  it('should validate recipent', function (done) {
    options.lifetimeInSeconds = 600;
    options.recipient = 'foo';
    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', recipientUrl: 'bar'});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.exists(err);
      err.message.should.equal('Recipient is invalid. Configured: bar');
      should.not.exists(profile);
      done();
    });

  });

  it('should extract authentication context from assertion as a user prop', function (done) {

    var options = {
      cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
      key: fs.readFileSync(__dirname + '/test-auth0.key'),
      issuer: 'urn:issuer',
      lifetimeInSeconds: 600,
      audiences: 'urn:myapp',
      attributes: {
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'сообщить@bar.com',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'сообщить вКонтакте'
      },
      nameIdentifier:       'вКонтакте',
      nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    };

    var signedAssertion = saml20.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {
      if (error) return done(error);
      
      assert.ok(profile);
      assert.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod']);
      
      done();
    });

  });


});
