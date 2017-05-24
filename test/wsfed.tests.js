var expect = require('chai').expect;
var server = require('./fixture/wsfed-server');
var request = require('request');
var cheerio = require('cheerio');

describe('wsfed', function () {
  before(function (done) {
    server.start(done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('normal flow', function () {
    var user, r, bod, $;

    before(function (done) {
      request.get({
        jar: request.jar(),
        uri: 'http://localhost:5050/login?wa=wsignin1.0&wtrealm=urn:fixture-test'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);


        $ = cheerio.load(b);
        var wresult = $('input[name="wresult"]').attr('value');
        var wa = $('input[name="wa"]').attr('value');

        request.post({
          jar: request.jar(),
          uri: 'http://localhost:5050/callback',
          form: { wresult: wresult, wa: wa }
        }, function(err, response, body) {
          if(err) return done(err);

          r = response;
          bod = body;
          done();
        });
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'])
          .to.equal(server.fakeUser.id);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'])
          .to.equal(server.fakeUser.emails[0].value);
    });

  });

  describe('wresult without RequestedSecurityToken', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5050/callback',
        form: { wresult: '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"></t:RequestSecurityTokenResponse>' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('missing wresult in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5050/callback'
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });
  });

  describe('invalid wresult in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5050/callback',
        form: { wresult: 'foo' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('invalid wresult (xml) in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5050/callback/wresult-with-invalid-xml',
        form: { wresult: '<t:RequestSecurityTokenResponse Context="undefined" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken></saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="_dpEiwydz8xWGlw4HbWMg1XfOUdEpdaMC" IssueInstant="2017-05-24T17:52:42.498Z" Issuer="urn:fixture-test"><saml:Conditions NotBefore="2017-05-24T17:52:42.498Z" NotOnOrAfter="2017-05-25T01:52:42.498Z"><saml:AudienceRestrictionCondition><saml:Audience>urn:fixture-test</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="nameidentifier"><saml:AttributeValue>12345678</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="emailaddress"><saml:AttributeValue>jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="name"><saml:AttributeValue>John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="givenname"><saml:AttributeValue>John</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="surname"><saml:AttributeValue>Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="2017-05-25T01:52:42.498Z"><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject></saml:AuthenticationStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_dpEiwydz8xWGlw4HbWMg1XfOUdEpdaMC"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>fxxeOWyp3M3cVfglUEg0Fc0mVAm7QVCyrSX2Kflq8VE=</DigestValue></Reference></SignedInfo><SignatureValue>ETv7SqrEoHYP1FTLcdylyDZotyJ1uuNNCLo6sw4cm4YAnGz/OYUIssUb0s82C3NCfV5ifvryr5khnZCNfRvEWJPsIZAtaSPHeeO+x3ajIDd/qfklNBHpdEYMP2WbcqPA6pYeh+OHgAlG6srsLDO8fMymUa/T8yACIU7cwnouEaYESWRU2fqKOXpeUxB/pENiY+qxPTvxzRYld5OlR+sNAJFPIvl3V5G+vw0mx+7tZteKq7yX0djpwEoFfXAcMzvLoqLqENjxPanmVPv7qvv7dIdI0kPE6jret50sHkHpQ7XZJmGi6cNc+/kvhSHXhD3vJ0u3BP/qCCPYPHz42z+KIw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></saml:Assertion></t:RequestedSecurityToken></t:RequestSecurityTokenResponse>' }
      },
      function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });

    it('should be recognized as an invalid xml', function(){
      var err = JSON.parse(bod);
      expect(err.message)
          .to.equal('wresult should be a valid xml');;
    });
  });
});
