var assert = require('assert'),
    fs = require('fs'),
    helpers = require('./helpers'),
    should = require('should'),
    saml20 = require('saml').Saml20,
    utils = require('../lib/passport-wsfed-saml2/utils'),
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
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
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

  it('should ignore the NameQualifier validation when nameid format is "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"', function (done) {
    var signedAssertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_ne0Z8R1z9xdbekXeWrAAg7srNB78exsb" IssueInstant="2016-08-02T21:54:04.971Z"><saml:Issuer>urn:issuer</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_ne0Z8R1z9xdbekXeWrAAg7srNB78exsb"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>p7iHnIt5xJZNimGNxh4d9R2J7DML8WNrMwMxmZ1WwSU=</DigestValue></Reference></SignedInfo><SignatureValue>pb1Wp/LFbigEj+TNm7gkAwlfIc17LNwUXVTgM8RQnMvYJfIPZbl1yo5xMCh6ObMFwCs1T+gKI5C7jMloX2QhWD/XUffBKiDfkZUg7NI/Jyt5m+Bdst12SNhHBVsNilL9ZCuf+QtQD7301gUhVHP6Ramf4y+XNod9AfzhFLYNfl6fhf/5KA/KkjiOwYW5Ps/43OMXXSeVaeQ7JRU8XqyKbwlB+YXGseFLnyZopv8Cw9Bb2935ADLX111oFBkiRhnMUJW0LMbSWM6UVJ4V0qoW9h+f3isN5+R87RECNeAQP3WSBiddnEuSdhgQYQVnb6s0mThpvs7uvIOlog0FqeSrvQ==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="name-qualifier">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-08-02T22:04:04.971Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-08-02T21:54:04.971Z" NotOnOrAfter="2016-08-02T22:04:04.971Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-08-02T21:54:04.971Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>';

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkExpiration: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
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

  it('should ignore the SPNameQualifier validation when the nameid format is "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"', function (done) {
    var signedAssertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_nPmKm9IskDCo61hUea4DX7o3POLbLcUK" IssueInstant="2016-08-02T21:59:48.654Z"><saml:Issuer>urn:issuer</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_nPmKm9IskDCo61hUea4DX7o3POLbLcUK"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>UYsy9NacnRqnSTbidM8WBBgS+Op0G05iBJTX0T1WlUk=</DigestValue></Reference></SignedInfo><SignatureValue>VzRQaMR5Qk1P+g1tqJRKroq4JJx00FZ0rZxO4vG2gGkBXJ8262B4VUHOkxyPHNH1l/DuxSnNsL8AAbZfn8EdxMdToPvm2hkqygyA5W20o6g6eSC41rDOavTzesOKoXn3Uq9DOiUXve5ieYYCt5bQcoSCVT6uhVEKMhdcLhaB507qj9Gzcfp0E4F57ezRTTnVVEF/wCJ5j0QTMA2Wh09fxNkGijlE8KHzDJZapN4tDCzmK8qY7211gKuTfKYJGXYA4hSxw9fiQGDEPKRYA6tWf0HO5Vd8edRg2ZHr7AgjuCPp5Fj8VOP+KppA1YFBbq4Eqqt6KHg91KJlGs3ivpmwPw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" SPNameQualifier="other-qualifier">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-08-02T22:09:48.654Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-08-02T21:59:48.654Z" NotOnOrAfter="2016-08-02T22:09:48.654Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-08-02T21:59:48.654Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>';

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkExpiration: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
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

   it('should validate the NameQualifier when nameid format is "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"', function (done) {
    var signedAssertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_dZZwXmRpwYcaIdFA5l0qSCCuu0if9UNo" IssueInstant="2016-09-29T12:34:13.488Z"><saml:Issuer>urn:issuer</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_dZZwXmRpwYcaIdFA5l0qSCCuu0if9UNo"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>ndqj65JwACeDERG2aZF6k0IF85KshkhgILzxhbKRyiw=</DigestValue></Reference></SignedInfo><SignatureValue>LPcIU9W9HmX1QM+baMPLTj9StBFRksnDoFn/HVd8uLJgdH8Xeiv9TOQGElmSaBLypjCeN6ILq6pcZ0mxMC9zfd9X3WKmYtcrGI1BugATeNsqUm63x+Msau8pNuZrNNbfIQvLooMhF4T92ym2ADSm+zCQVNwBH7/v0rVIE6MEy8AYqqfpvH9CR88XQYMCSgKN0JQ2FPbcHvhIX7Hl+xG6PSzgfznE8dcWBUi24FajyGpqlNm8O3uHCfjR3wzO42UQIJFOJOiLb7QGNyWE1KXKYWyzZgAxGQuRUcbYxcnKTbVK3b3TBH+p2ZR+a2ktKmvqNBvQxy6tE4UXDIIpvmknSw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="invalid-value">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-09-29T12:44:13.488Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-09-29T12:34:13.488Z" NotOnOrAfter="2016-09-29T12:44:13.488Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-09-29T12:34:13.488Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>';

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkExpiration: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      assert.equal(err.message, 'NameQualifier attribute in the NameID element does not match urn:issuer');
      done();
    });
  });

  it('should validate the SPNameQualifier when the nameid format is "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"', function (done) {
    var signedAssertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl" IssueInstant="2016-09-29T12:35:22.345Z"><saml:Issuer>urn:issuer</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Gsh2DubHXYDeuHyBa+DU1k5G43UjyQsyPRYVgEqpTD8=</DigestValue></Reference></SignedInfo><SignatureValue>mubsqLCaM16gT2rAFLl8XDuLWTALH6cdRMM/kNHLpVzO5PA6FGVPX5ojW2UCKGOhGHn0Hd/mYCOCtgAROphWjxpQl5TDyeQE0frjKs8ik0V/Jjy5T6PeWKHLqN6sHbP6YpkGixshCWtop8JOs6SijM9PBGnWal6Nx5bUMBfAyUnGyIhLwNaE8Z4NHkyAqmdxgLS0e8w5qngKQaUlyERZCrqKQ4w8VaHFG4Dos36XVfh+U7udo3IlbrpBLsu9xG1Azxe2iPC6+84xC09P6EvQylvTnz5NU4jhk10SmmRjZ6AVvzJTz/gbVfRfZoEAUhCuIIh3HuRwf400ESf38ouZTA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="invalid-value">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-09-29T12:45:22.345Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-09-29T12:35:22.345Z" NotOnOrAfter="2016-09-29T12:45:22.345Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-09-29T12:35:22.345Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>';

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkExpiration: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      assert.equal(err.message, 'SPNameQualifier attribute in the NameID element does not match urn:myapp');
      done();
    });
  });

  it('should parse attributes with multiple values', function (done) {

    options.attributes = {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups': ['Admins', 'Contributors']
    };

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      if (err) return done(err);

      assert.ok(profile);
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.be.an.instanceOf(Array);
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.include('Admins');
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups'].should.include('Contributors');
      done();
    });

  });

  it('should validate expiration with default clockSkew', function (done) {

    options.lifetimeInSeconds = -240;

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.exists(err);
      err.message.should.equal('assertion has expired.');
      should.not.exists(profile);

      done();
    });

  });

  it('should validate expiration with overriden clockSkew', function (done) {

    options.lifetimeInSeconds = -240;

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, clockSkew: 5});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.not.exists(err);
      should.exists(profile);

      done();
    });

  });


  it('should should allow expired cert if option not passed', function (done) {

    options.lifetimeInSeconds = 10000;

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    // The embedded cert is expired, so we can use this as is.
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.not.exists(err);
      should.exists(profile);
      done();
    });

  });

  it('should validate certificate expiration with embedded cert', function (done) {

    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    // The embedded cert is expired, so we can use this as is.
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkCertExpiration: true});
    samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.exists(err);
      err.message.should.equal('The signing certificate is not currently valid.');
      should.not.exists(profile);

      done();
    });

  });


  it('should validate certificate expiration with non-embedded cert', function (done) {

    var signedAssertion = saml20.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    // The test cert is expired, so we can use this as is.
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false, checkCertExpiration: true});
    const parsedAssertion = utils.parseSamlAssertion(signedAssertion);
    assert.equal(parsedAssertion.getElementsByTagName("X509Certificate").length, 1); // Make sure we start with exactly one embedded cert
    const embeddedCert = parsedAssertion.getElementsByTagName("X509Certificate")[0]
    embeddedCert.parentNode.removeChild(embeddedCert);
    assert.equal(parsedAssertion.getElementsByTagName("X509Certificate").length, 0); // Make sure we removed the cert(s)

    samlPassport.validateSamlAssertion(parsedAssertion, function(err, profile) {
      should.exists(err);
      err.message.should.equal('The signing certificate is not currently valid.');
      should.not.exists(profile);

      done();
    });

  });

  it('should validate recipent', function (done) {
    options.lifetimeInSeconds = 600;
    options.recipient = 'foo';
    var signedAssertion = saml20.create(options);
    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', recipientUrl: 'bar'});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
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
    const samlPassport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient: false});
    var profile = samlPassport.validateSamlAssertion(signedAssertion, function(error, profile) {
      if (error) return done(error);

      assert.ok(profile);
      assert.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod']);

      done();
    });
  });

  it('should fail when the X509Certificate is invalid', function (done) {
    const signedAssertion = fs.readFileSync(__dirname + '/samples/plain/samlresponse_saml20_invalid_cert.txt').toString();
    const options = {
      checkDestination: false,
      thumbprint: '119B9E027959CDB7C662CFD075D9E2EF384E445F'
    };

    const samlPassport = new SamlPassport(options);
    const profile = samlPassport.validateSamlAssertion(signedAssertion, function(err, profile) {
      should.exists(err);
      let oldNpmMessage  = 'The signing certificate is invalid (PEM_read_bio_PUBKEY failed)';
      let newNpmMessage = 'The signing certificate is invalid (error:0906700D:PEM routines:PEM_ASN1_read_bio:ASN1 lib, error:0D07803A:asn1 encoding routines:ASN1_ITEM_EX_D2I:nested asn1 error, error:0D068066:asn1 encoding routines:ASN1_CHECK_TLEN:bad object header)';
      let node10Message = 'The signing certificate is invalid (error:0D07803A:asn1 encoding routines:asn1_item_embed_d2i:nested asn1 error, error:0D068066:asn1 encoding routines:asn1_check_tlen:bad object header)'
      assert.ok(
        err.message === oldNpmMessage || err.message === newNpmMessage || err.message === node10Message,
        'Error message for invalid certificate is incorrect'
      );
      done();
    });
  });

  describe('validate saml assertion (signature checks)', function(){
    it('should fail when signature is not found', function (done) {
      const assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl" IssueInstant="2016-09-29T12:35:22.345Z"><saml:Issuer>urn:issuer</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="invalid-value">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-09-29T12:45:22.345Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-09-29T12:35:22.345Z" NotOnOrAfter="2016-09-29T12:45:22.345Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-09-29T12:35:22.345Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>';

      var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
      const samlPassport = new SamlPassport({ cert: publicKey, realm: 'urn:myapp', checkRecipient: false });
      var profile = samlPassport.validateSamlAssertion(assertion, function (err, profile) {
        assert.ok(err);
        assert.ok(!profile);
        assert.equal(err.message, "Signature is missing (xpath: /*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#'])");
        done();
      });
    });

    it('should fail when signature is found twice', function (done) {
      const assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl" IssueInstant="2016-09-29T12:35:22.345Z"><saml:Issuer>urn:issuer</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Gsh2DubHXYDeuHyBa+DU1k5G43UjyQsyPRYVgEqpTD8=</DigestValue></Reference></SignedInfo><SignatureValue>mubsqLCaM16gT2rAFLl8XDuLWTALH6cdRMM/kNHLpVzO5PA6FGVPX5ojW2UCKGOhGHn0Hd/mYCOCtgAROphWjxpQl5TDyeQE0frjKs8ik0V/Jjy5T6PeWKHLqN6sHbP6YpkGixshCWtop8JOs6SijM9PBGnWal6Nx5bUMBfAyUnGyIhLwNaE8Z4NHkyAqmdxgLS0e8w5qngKQaUlyERZCrqKQ4w8VaHFG4Dos36XVfh+U7udo3IlbrpBLsu9xG1Azxe2iPC6+84xC09P6EvQylvTnz5NU4jhk10SmmRjZ6AVvzJTz/gbVfRfZoEAUhCuIIh3HuRwf400ESf38ouZTA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="invalid-value">foo</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-09-29T12:45:22.345Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-09-29T12:35:22.345Z" NotOnOrAfter="2016-09-29T12:45:22.345Z"><saml:AudienceRestriction><saml:Audience>urn:myapp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">foo@bar.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">Foo Bar</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2016-09-29T12:35:22.345Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_muhd3ZBmN9LK3Ev08rkc8CA40YvNOkGl"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Gsh2DubHXYDeuHyBa+DU1k5G43UjyQsyPRYVgEqpTD8=</DigestValue></Reference></SignedInfo><SignatureValue>mubsqLCaM16gT2rAFLl8XDuLWTALH6cdRMM/kNHLpVzO5PA6FGVPX5ojW2UCKGOhGHn0Hd/mYCOCtgAROphWjxpQl5TDyeQE0frjKs8ik0V/Jjy5T6PeWKHLqN6sHbP6YpkGixshCWtop8JOs6SijM9PBGnWal6Nx5bUMBfAyUnGyIhLwNaE8Z4NHkyAqmdxgLS0e8w5qngKQaUlyERZCrqKQ4w8VaHFG4Dos36XVfh+U7udo3IlbrpBLsu9xG1Azxe2iPC6+84xC09P6EvQylvTnz5NU4jhk10SmmRjZ6AVvzJTz/gbVfRfZoEAUhCuIIh3HuRwf400ESf38ouZTA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></saml:Assertion>';

      var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
      const samlPassport = new SamlPassport({ cert: publicKey, realm: 'urn:myapp', checkRecipient: false });
      var profile = samlPassport.validateSamlAssertion(assertion, function (err, profile) {
        assert.ok(err);
        assert.ok(!profile);
        assert.equal(err.message, "Signature was found more than one time (xpath: /*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#'])");
        done();
      });
    });
  });

});
