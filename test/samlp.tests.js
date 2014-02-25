var expect = require('chai').expect;
var server = require('./fixture/samlp-server');
var request = require('request');
var qs = require('querystring');
var cheerio = require('cheerio');
var xmldom = require('xmldom');
var Samlp = require('../lib/passport-wsfed-saml2/samlp');
var fs = require('fs');

describe('samlp (functional tests)', function () {
  before(function (done) {
    server.start(done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('samlp flow with assertion signed', function () {
    var r, bod;
    
    before(function (done) {
      // this samlp request comes from Salesforce
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
                  'http://localhost:5051/callback', function(err, resp) {
        if (err) return done(err);
        if (resp.response.statusCode !== 200) return done(new Error(resp.body));
        r = resp.response;
        bod = resp.body;
        done();
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

  describe('samlp flow with assertion signed with different cert', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('samlp flow with response signed', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse', function(err, resp) {
        if (err) return done(err);
        if (resp.response.statusCode !== 200) return done(new Error(resp.body));
        r = resp.response;
        bod = resp.body;
        done();
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

  describe('samlp flow with response signed with different cert', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('missing SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5051/callback'
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
      expect(r.headers.location.split('?')[0])
            .to.equal('http://localhost:5051/samlp');
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      expect(querystring).to.have.property('RelayState');
    });
  });

  describe('invalid SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5051/callback',
        form: { SAMLResponse: 'foo' }
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

  describe('samlp request', function () {
    var r, bod;
    
    before(function (done) {
      request.get({
        jar: request.jar(), 
        followRedirect: false,
        uri: 'http://localhost:5051/login'
      }, function (err, resp, b){
        if(err) return callback(err);
        r = resp;
        bod = b;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });

    it('should have SAMLRequest querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
    });

    it('should have RelayState querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('RelayState');
      expect(querystring.RelayState).to.equal(server.relayState);
    });

  });

  describe('samlp request with idp url containing querystring', function () {
    var r, bod;
    
    before(function (done) {
      request.get({
        jar: request.jar(), 
        followRedirect: false,
        uri: 'http://localhost:5051/login-idp-with-querystring'
      }, function (err, resp, b){
        if(err) return callback(err);
        r = resp;
        bod = b;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });

    it('should have SAMLRequest and foo in querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      expect(querystring).to.have.property('foo');
    });

  });

});

describe('samlp (unit tests)', function () {

  describe('extractAssertion', function () {

    var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_0d2a510bffbb012bbc30" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_241siKCvX3e3oRGYtkdcV4DfGDtIsVk4" IssueInstant="2014-02-25T15:20:20.535Z"><saml:Issuer>urn:fixture-test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-02-25T16:20:20.535Z" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-02-25T15:20:20.535Z" NotOnOrAfter="2014-02-25T16:20:20.535Z"><saml:AudienceRestriction><saml:Audience>https://auth0-dev-ed.my.salesforce.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><saml:AttributeValue xsi:type="xs:anyType">12345678</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><saml:AttributeValue xsi:type="xs:anyType">John</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><saml:AttributeValue xsi:type="xs:anyType">Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2014-02-25T15:20:20.535Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_0d2a510bffbb012bbc30"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YkV3DdlEa19Gb0eE3jTYTVPalV1kZ88fbIv4blO9T1Y=</DigestValue></Reference></SignedInfo><SignatureValue>ZiINpNlahQlp1JbgFsamI1/pZ+zcPsZboESVayxBMtrUBYNC4IG2VBnqku7paDxJQ7624CvcNzAYWYCv/2/c67Bv6YhQwK1rb4DPEL6OvbI8FNkYAhTNNw5UhUTEMjnJ7AncV/svUTYyIOyktuCvQh3tR4teZJV+BM3IKj9vRQQbCRNSUVHJEe963ma5HcCyo+RhIKU1pm4+ycswOlY9F115roKB4RNRJLs7Z5fyzhbOoCUujR9MMKHHq+CWaYvh5SkjaH1wMorlPlJtq5dhTZtDRhj4HwxYpCG5b4NF2vp+Jpni4dDFKou0Lzk0k6ueCJGcNHfidfEB3RB20Hed2g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></samlp:Response>';
    var samlpReponseWithEncryptedAssertion = '<samlp:Response ID="_66a4b25c-2d88-492e-a730-7ea462cdd9ba" Version="2.0" IssueInstant="2014-02-11T15:44:44.598Z" Destination="https://fmi-test.auth0.com/login/callback" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_d4f0e231c8b038213f27" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" > <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://adfs.fmi.ch/adfs/services/trust</Issuer> <samlp:Status> <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /> </samlp:Status> <EncryptedAssertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"> <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" > <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" /> <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"> <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#"> <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"> <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /> </e:EncryptionMethod> <KeyInfo> <ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> <ds:X509IssuerSerial> <ds:X509IssuerName>CN=fmi-test.auth0.com</ds:X509IssuerName> <ds:X509SerialNumber>17575331292066593326</ds:X509SerialNumber> </ds:X509IssuerSerial> </ds:X509Data> </KeyInfo> <e:CipherData> <e:CipherValue>PfbLmL7Eb2NL5lzxyuEuKolgDtHjAuVDV9AaDKp1UqxSKXPGQaF3FTFt7Gl7FRmEdfjMD4xyMII4c6itasV7/N1WIXVw6j9VpvBZ2WPH4lT2gHVXEnCSko+rlk0OfFQN/XFY1HZrPb0PeSYtbuR6Fe2KDLVYYSElrGyn9lbU/zgLB+cV3OiidMamymcTjBYxr3+wv8zhEl2jDYd/04wULeDydhNpA8KFzjy/DQwE4GwlOfuCCtZboai1OXA3++KEuwH2QrC5lRpmnpwV1OJj+ozWDmJrRLA/vpxakQfMzjBcMoBx5wy0dvDaXcjMZk2aaOUhydSC+vd5UYD3npVlog==</e:CipherValue> </e:CipherData> </e:EncryptedKey> </KeyInfo> <xenc:CipherData> <xenc:CipherValue>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</xenc:CipherValue> </xenc:CipherData> </xenc:EncryptedData> </EncryptedAssertion> </samlp:Response>';

    it('should returns assertion', function (done) {
      var samlp = new Samlp({});
      samlp.extractAssertion(samlpResponse, function (err, assertion) {
        if (err) { done(err); }
        
        var doc = new xmldom.DOMParser().parseFromString(assertion.toString());
        var attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
        expect(attributes.length).to.equal(5);
        expect(attributes[0].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier');
        expect(attributes[0].firstChild.textContent).to.equal('12345678');
        expect(attributes[1].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
        expect(attributes[1].firstChild.textContent).to.equal('jfoo@gmail.com');
        expect(attributes[2].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name');
        expect(attributes[2].firstChild.textContent).to.equal('John Foo');
        expect(attributes[3].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname');
        expect(attributes[3].firstChild.textContent).to.equal('John');
        expect(attributes[4].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname');
        expect(attributes[4].firstChild.textContent).to.equal('Foo');
        done();
      });
    });

    it('should throws error if EncryptedAssertion is present but options.encryptionKey was not specified', function (done) {
      var samlp = new Samlp({});
      samlp.extractAssertion(samlpReponseWithEncryptedAssertion, function (err) {
        expect(err.message).to.equal('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.');
        done();
      });
    });

    it('should returns decrypted assertion', function (done) {
      var samlp = new Samlp({
        decryptionKey: fs.readFileSync(__dirname + '/test-decryption.key')
      });

      samlp.extractAssertion(samlpReponseWithEncryptedAssertion, function (err, assertion) {
        if (err) { done(err); }

        var doc = new xmldom.DOMParser().parseFromString(assertion.toString());
        var attributes = doc.documentElement.getElementsByTagName('Attribute');
        expect(attributes.length).to.equal(8);
        expect(attributes[0].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
        expect(attributes[1].getAttribute('Name')).to.equal('urn:oid:0.9.2342.19200300.100.1.3');
        expect(attributes[2].getAttribute('Name')).to.equal('urn:oid:2.16.756.1.2.5.1.1.4');
        expect(attributes[2].firstChild.textContent).to.equal('fmi.ch');
        expect(attributes[3].getAttribute('Name')).to.equal('urn:oid:2.16.756.1.2.5.1.1.5');
        expect(attributes[3].firstChild.textContent).to.equal('others');
        expect(attributes[4].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname');
        expect(attributes[4].firstChild.textContent).to.equal('Pan');
        expect(attributes[5].getAttribute('Name')).to.equal('urn:oid:2.5.4.4');
        expect(attributes[5].firstChild.textContent).to.equal('Pan');
        expect(attributes[6].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname');
        expect(attributes[6].firstChild.textContent).to.equal('Peter');
        expect(attributes[7].getAttribute('Name')).to.equal('urn:oid:2.5.4.42');
        expect(attributes[7].firstChild.textContent).to.equal('Peter');
        done();
      });
    });

  });

});

function doSamlpFlow(samlRequestUrl, callbackEndpoint, callback) {
  request.get({
    jar: request.jar(), 
    uri: samlRequestUrl
  }, function (err, response, b){
    if(err) return callback(err);
    expect(response.statusCode)
      .to.equal(200);

    var $ = cheerio.load(b);
    var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
    var RelayState = $('input[name="RelayState"]').attr('value');
    

    request.post({
      jar: request.jar(), 
      uri: callbackEndpoint,
      form: { SAMLResponse: SAMLResponse, RelayState: RelayState }
    }, function(err, response, body) {
      if(err) return callback(err);
      callback(null, { response: response, body: body });
    });
  });
}