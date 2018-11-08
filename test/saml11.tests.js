var assert = require('assert'),
    fs = require('fs'),
    helpers = require('./helpers'),
    should = require('should'),
    saml11 = require('saml').Saml11,
    SamlPassport = require('../lib/passport-wsfed-saml2/saml').SAML;

describe('saml 1.1 assertion', function () {

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

    var signedAssertion = saml11.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient : false});
    saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {

      assert.ok(profile);
      assert.equal('foo', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']);
      assert.equal('Foo Bar', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']);
      assert.equal('foo@bar.com', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
      assert.equal('foo@bar.com', profile['email']);
      assert.equal('urn:issuer', profile['issuer']);
      done();
    });

  });

  it('should handle unicode', function (done) {

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

    var signedAssertion = saml11.create(options);

    var publicKey = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var saml_passport = new SamlPassport({cert: publicKey, realm: 'urn:myapp', checkRecipient : false});
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {
      if (error) return done(error);

      assert.ok(profile);
      assert.equal('вКонтакте', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']);
      assert.equal('сообщить вКонтакте', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']);
      assert.equal('сообщить@bar.com', profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']);
      done();
    });

  });

  it('should validate an assertion from office365', function (done) {
    var signedAssertion = '<Assertion ID="_1b1ffaef-86ef-42e1-92cf-cf8c9d9a4ce0" IssueInstant="2013-04-02T18:50:24.000Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/75696069-df44-4310-9bcf-08b45e3007c9/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_1b1ffaef-86ef-42e1-92cf-cf8c9d9a4ce0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>TzJmLs0BTPgpaPLsA7L2Kd9l1k4IBOmwIM/znV2iOPU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>OHJCAffCNPRkwsE3RqnVPoCRSqsPrio8prABauzu2pqF418Y1QJuJehhzztY8A6kwnBUkBVE7BIyLe7kgCnBoNZWElYki1xtaLksc/Afc0TjlZvv9IJ9fQHIBiL1JA9KcySq1tu9dv/NauykBODXuljPuVTk6I4xLLWcg20o26Ov57axp42uWPpcJHtasomLmmmnAXEh6P7aB/1Vlm/MAJhWXToxacauJzFao3F9JNEuucKY6y3RPDp1Qq3vL0gq98RKuiaejayu6RjyyU2+8vCBzURul8b7ZXPUHfIOME6Q5LvbKqLhe/mzqRc+9GUg22X3B5SYjdnXjwHbBTbihA==</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>10030000838D23AF@MicrosoftOnline.com</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" /></Subject><Conditions NotBefore="2013-04-02T18:50:23.969Z" NotOnOrAfter="2013-04-03T06:50:23.969Z"><AudienceRestriction><Audience>spn:408153f4-5960-43dc-9d4f-6b717d772c8d</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>75696069-df44-4310-9bcf-08b45e3007c9</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Matias</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>matias@auth0.onmicrosoft.com</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Woloski</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/75696069-df44-4310-9bcf-08b45e3007c9/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2013-04-02T18:50:16.000Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>';

    var saml_passport = new SamlPassport({thumbprints: ['3464c5bdd2be7f2b6112e2f08e9c0024e33d9fe0'],
                                          realm: 'spn:408153f4-5960-43dc-9d4f-6b717d772c8d',
                                          checkRecipient: false,
                                          checkExpiration: false}); // dont check expiration since we are harcoding the token
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {

      assert.ok(profile);
      done();
    });

  });

  it('should return error if validation fails', function (done) {
    var signedAssertion = '<Assertion ID="_1b1ffaef-86ef-42e1-92cf-cf8c9d9a4ce0" IssueInstant="2013-04-02T18:50:24.000Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://sts.windows.net/75696069-df44-4310-9bcf-08b45e3007c9/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_1b1ffaef-86ef-42e1-92cf-cf8c9d9a4ce0"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>TzJmLs0BTPgpaPLsA7L2Kd9l1k4IBOmwIM/znV2iOPU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>OHJCAffCNPRkwsE3RqnVPoCRSqsPrio8prABauzu2pqF418Y1QJuJehhzztY8A6kwnBUkBVE7BIyLe7kgCnBoNZWElYki1xtaLksc/Afc0TjlZvv9IJ9fQHIBiL1JA9KcySq1tu9dv/NauykBODXuljPuVTk6I4xLLWcg20o26Ov57axp42uWPpcJHtasomLmmmnAXEh6P7aB/1Vlm/MAJhWXToxacauJzFao3F9JNEuucKY6y3RPDp1Qq3vL0gq98RKuiaejayu6RjyyU2+8vCBzURul8b7ZXPUHfIOME6Q5LvbKqLhe/mzqRc+9GUg22X3B5SYjdnXjwHbBTbihA==</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng</X509Certificate></X509Data></KeyInfo></ds:Signature><Subject><NameID>10030000838D23AF@MicrosoftOnline.com</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" /></Subject><Conditions NotBefore="2013-04-02T18:50:23.969Z" NotOnOrAfter="2013-04-03T06:50:23.969Z"><AudienceRestriction><Audience>spn:408153f4-5960-43dc-9d4f-6b717d772c8d</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid"><AttributeValue>75696069-df44-4310-9bcf-08b45e3007c9</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><AttributeValue>Matias</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><AttributeValue>matias@auth0.onmicrosoft.com</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><AttributeValue>Woloski</AttributeValue></Attribute><Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider"><AttributeValue>https://sts.windows.net/75696069-df44-4310-9bcf-08b45e3007c9/</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="2013-04-02T18:50:16.000Z"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>';

    var saml_passport = new SamlPassport({thumbprints: ['3464c5bdd2be7f2b6112e2f08e9c0024e33d9fe1', '3464c5bdd2be7f2b6112e2f08e9c0024e33d9fe2'], // WRONG thumbprints
                                          realm: 'spn:408153f4-5960-43dc-9d4f-6b717d772c8d',
                                          checkRecipient: false,
                                          checkExpiration: false}); // dont check expiration since we are harcoding the token
    var profile = saml_passport.validateSamlAssertion(signedAssertion, function(error, profile) {
      assert.equal('Invalid thumbprint (configured: 3464C5BDD2BE7F2B6112E2F08E9C0024E33D9FE1, 3464C5BDD2BE7F2B6112E2F08E9C0024E33D9FE2. calculated: 3464C5BDD2BE7F2B6112E2F08E9C0024E33D9FE0)', error.message);
      done();
    });

  });

  it('should fail when the X509Certificate is invalid', function (done) {
    const signedAssertion = fs.readFileSync(__dirname + '/samples/plain/samlresponse_saml11_invalid_cert.txt').toString();
    const options = {
      checkDestination: false,
      thumbprint: '119B9E027959CDB7C662CFD075D9E2EF384E445F'
    };

    const saml_passport = new SamlPassport(options);
    const profile = saml_passport.validateSamlAssertion(signedAssertion, function(err, profile) {
      let oldNpmMessage = 'The signing certificate is invalid (PEM_read_bio_PUBKEY failed)';
      let newNpmMessage = 'The signing certificate is invalid (error:0906700D:PEM routines:PEM_ASN1_read_bio:ASN1 lib, error:0D07803A:asn1 encoding routines:ASN1_ITEM_EX_D2I:nested asn1 error, error:0D068066:asn1 encoding routines:ASN1_CHECK_TLEN:bad object header)';
      let node10Message = 'The signing certificate is invalid (error:0D07803A:asn1 encoding routines:asn1_item_embed_d2i:nested asn1 error, error:0D068066:asn1 encoding routines:asn1_check_tlen:bad object header)'

      assert.ok(err, 'The signing certificate was unexpectedly valid');
      assert.ok(/signing certificate is invalid/.test(err.message), 'Error message is not the default invalid message');
      assert.ok(
        err.message === oldNpmMessage || err.message === newNpmMessage || err.message === node10Message,
        'Error message for invalid certificate is incorrect'
      );

      done();
    });
  });
});
