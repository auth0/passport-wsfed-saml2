var expect  = require('chai').expect;
var xmldom  = require('xmldom');
var fs      = require('fs');
var zlib    = require('zlib');
var server  = require('./fixture/samlp-server');
var Samlp   = require('../lib/passport-wsfed-saml2/samlp');
var Saml    = require('../lib/passport-wsfed-saml2/saml').SAML;

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

    it('should returns assertion when the namespace is defined in Saml Response element instead of Assertion element', function (done) {
      var currentSamlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_0d2a510bffbb012bbc30" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="_241siKCvX3e3oRGYtkdcV4DfGDtIsVk4" IssueInstant="2014-02-25T15:20:20.535Z"><saml:Issuer>urn:fixture-test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-02-25T16:20:20.535Z" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-02-25T15:20:20.535Z" NotOnOrAfter="2014-02-25T16:20:20.535Z"><saml:AudienceRestriction><saml:Audience>https://auth0-dev-ed.my.salesforce.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><saml:AttributeValue xsi:type="xs:anyType">12345678</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><saml:AttributeValue xsi:type="xs:anyType">John</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><saml:AttributeValue xsi:type="xs:anyType">Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2014-02-25T15:20:20.535Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_0d2a510bffbb012bbc30"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YkV3DdlEa19Gb0eE3jTYTVPalV1kZ88fbIv4blO9T1Y=</DigestValue></Reference></SignedInfo><SignatureValue>ZiINpNlahQlp1JbgFsamI1/pZ+zcPsZboESVayxBMtrUBYNC4IG2VBnqku7paDxJQ7624CvcNzAYWYCv/2/c67Bv6YhQwK1rb4DPEL6OvbI8FNkYAhTNNw5UhUTEMjnJ7AncV/svUTYyIOyktuCvQh3tR4teZJV+BM3IKj9vRQQbCRNSUVHJEe963ma5HcCyo+RhIKU1pm4+ycswOlY9F115roKB4RNRJLs7Z5fyzhbOoCUujR9MMKHHq+CWaYvh5SkjaH1wMorlPlJtq5dhTZtDRhj4HwxYpCG5b4NF2vp+Jpni4dDFKou0Lzk0k6ueCJGcNHfidfEB3RB20Hed2g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></samlp:Response>';
      var samlp = new Samlp({});
      samlp.extractAssertion(currentSamlpResponse, function (err, assertion) {
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
        if (err) { return done(err); }

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

    it('should return error if more than one assertion is found', function (done) {
      var currentSamlResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_0d2a510bffbb012bbc30" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_241siKCvX3e3oRGYtkdcV4DfGDtIsVk4" IssueInstant="2014-02-25T15:20:20.535Z"><saml:Issuer>urn:fixture-test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-02-25T16:20:20.535Z" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-02-25T15:20:20.535Z" NotOnOrAfter="2014-02-25T16:20:20.535Z"><saml:AudienceRestriction><saml:Audience>https://auth0-dev-ed.my.salesforce.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><saml:AttributeValue xsi:type="xs:anyType">12345678</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><saml:AttributeValue xsi:type="xs:anyType">John</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><saml:AttributeValue xsi:type="xs:anyType">Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2014-02-25T15:20:20.535Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_241siKCvX3e3oRGYtkdcV4DfGDtIsVk4" IssueInstant="2014-02-25T15:20:20.535Z"><saml:Issuer>urn:fixture-test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-02-25T16:20:20.535Z" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-02-25T15:20:20.535Z" NotOnOrAfter="2014-02-25T16:20:20.535Z"><saml:AudienceRestriction><saml:Audience>https://auth0-dev-ed.my.salesforce.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><saml:AttributeValue xsi:type="xs:anyType">12345678</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><saml:AttributeValue xsi:type="xs:anyType">John</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><saml:AttributeValue xsi:type="xs:anyType">Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2014-02-25T15:20:20.535Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_0d2a510bffbb012bbc30"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YkV3DdlEa19Gb0eE3jTYTVPalV1kZ88fbIv4blO9T1Y=</DigestValue></Reference></SignedInfo><SignatureValue>ZiINpNlahQlp1JbgFsamI1/pZ+zcPsZboESVayxBMtrUBYNC4IG2VBnqku7paDxJQ7624CvcNzAYWYCv/2/c67Bv6YhQwK1rb4DPEL6OvbI8FNkYAhTNNw5UhUTEMjnJ7AncV/svUTYyIOyktuCvQh3tR4teZJV+BM3IKj9vRQQbCRNSUVHJEe963ma5HcCyo+RhIKU1pm4+ycswOlY9F115roKB4RNRJLs7Z5fyzhbOoCUujR9MMKHHq+CWaYvh5SkjaH1wMorlPlJtq5dhTZtDRhj4HwxYpCG5b4NF2vp+Jpni4dDFKou0Lzk0k6ueCJGcNHfidfEB3RB20Hed2g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></samlp:Response>';
      var samlp = new Samlp({});
      samlp.extractAssertion(currentSamlResponse, function (err, assertion) {
        expect(err).to.exist;
        expect(assertion).not.to.exist;
        expect(err).to.have.a.property('message', 'A SAMLResponse can contain only one Assertion element.');
        done();
      });
    });

  });

  describe('validateSamlResponse', function(){
    var samlpResponseWithStatusResponder = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/><samlp:StatusMessage>specific error message</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderAndAuthnFailed = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" /></samlp:StatusCode></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderAndAuthnFailedWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" /></samlp:StatusCode><samlp:StatusMessage>specific error message</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusRequesterWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusMessage>signature required</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusRequesterWithoutMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusVersionMismatchWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" /><samlp:StatusMessage>version mismatch error</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusVersionMismatchWithoutMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" /></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusNotMappedStatus = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>';
    var xmlWithNoSamlResponse = '<myxml>somedata</myxml>';
    var xmlWithSeveralSamlResponseElements = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status></samlp:Response></samlp:Response>';

    it('should return error for AuthnFailed status with generic message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderAndAuthnFailed, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The responding provider was unable to successfully authenticate the principal');
        done();
      });
    });

    it('should return error for AuthnFailed status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderAndAuthnFailedWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('specific error message');
        done();
      });
    });

    it('should return error for Responder status with generic message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponder, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The request could not be performed due to an error on the part of the SAML responder or SAML authority');
        done();
      });
    });

    it('should return error for Responder status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('specific error message');
        done();
      });
    });

    it('should return error for Requester status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusRequesterWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('signature required');
        done();
      });
    });

    it('should return error for Requester status with default message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusRequesterWithoutMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The request could not be performed due to an error on the part of the requester');
        done();
      });
    });

    it('should return error for VersionMismatch status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusVersionMismatchWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('version mismatch error');
        done();
      });
    });

    it('should return error for VersionMismatch status with default message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusVersionMismatchWithoutMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The SAML responder could not process the request because the version of the request message was incorrect.');
        done();
      });
    });

    it('should return error when saml response is not found on the xml', function(done){
      var samlp = new Samlp({});
      samlp.validateSamlResponse(xmlWithNoSamlResponse, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('XML is not a valid saml response');
        done();
      });
    });

    it('should return error when saml response is found more than once', function(done){
      var samlp = new Samlp({});
      samlp.validateSamlResponse(xmlWithSeveralSamlResponseElements, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('SAMLResponse should be unique');
        done();
      });
    });

    it('should return \'saml response does not contain an Assertion element\' error', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusNotMappedStatus, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('saml response does not contain an Assertion element (Status: urn:oasis:names:tc:SAML:2.0:status:Success)');
        done();
      });
    });

    it('should return error for Destination does not match', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid' });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Destination endpoint https://auth0-dev-ed.my.salesforce.com did not match invalid');
        done();
      });
    });

    it('should return error for if isValidResponseID fails', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid', isValidResponseID: function(samlResponseID, done) {
        return done(new Error('Invalid response id'))
      } });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Invalid response id');
        done();
      });
    });

    it('should not return ResponseID validation error for if isValidResponseID fails but the check is disabled', function(done){
      var isValidResponseID = function(samlResponseID, done) {
        return done(new Error('Invalid response id'))
      }
      var samlp = new Samlp({ destinationUrl: 'invalid', checkResponseID: false, isValidResponseID: isValidResponseID });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).not.to.equal('Invalid response id');
        expect(err.message).to.equal('Destination endpoint https://auth0-dev-ed.my.salesforce.com did not match invalid');
        done();
      });
    });

    it('should return error for if isValidInResponseTo fails', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid', isValidInResponseTo: function(inReponseTo, done) {
        return done(new Error('Invalid inResponseTo'))
      } });

      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Invalid inResponseTo');
        done();
      });
    });

    it('should not return InResponseTo validation error for if isValidInResponseTo fails but the check is disabled', function(done){
      var isValidInResponseTo = function(inReponseTo, done) {
        return done(new Error('Invalid inResponseTo'))
      }
      var samlp = new Samlp({ destinationUrl: 'invalid', checkInResponseTo: false, isValidInResponseTo: isValidInResponseTo });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error'); //Destination is invalid
        expect(err.message).not.to.equal('Invalid inResponseTo');
        expect(err.message).to.equal('Destination endpoint https://auth0-dev-ed.my.salesforce.com did not match invalid');
        done();
      });
    });

    it('should return profile even if the namespace is in response element', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var encodedSamlResponse = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOng1MDA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm9maWxlczphdHRyaWJ1dGU6WDUwMCIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIgSUQ9InBmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmU+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+d0ZLLy9YN0dBdzVQQlFIbnRQV2I4T1RoWkVFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT50SWI4WjZPV3ExVDBzd3M2SkZkQWJVUjZGRUJrM0k3TmtYZ2s1d0N0NDJ0TWpQcTM0M2o4YWoxeHdKcXNiWXZMVHZBdHhFZ21vaGd4dmNKN29BRGlxWEJnRFE2SEpOeGUzVTZxM05HTzZRN1hobXRITUZOK2JmK0JsVDdIbGw2TWExMUJmWU5pNnJLblJPcUpUTDZlem01M2pMTm5xazlFbi9HWXdjQUttR0kxQzF4bEo5Y1FEdUh6QTZ3NTdUZXhkQU9YbkJWTWk1MG9Bb0FHOHRhVURXdHBwUXdmdXVDRitEN056NVFvVU5VS0UvRXh0VGpyaUJnMDRSWHY2Z0ZUS3FZYmViNHFETUlxZjZoZ3BWZDF4cm9aaXBHZlFodUhvY2pvVUtRU2ZTUDhCRFlEVFpveFZJaUVCVUhQOFJSSzVYb2Y0NXgwK2ZZajErTzdrZzhWcEE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0iaWQtWS1Sd0hpNlJQOGpNVVI4a3IxRlZ6SHVOdmJ1ck9JZUs2d0dwTmpkLSIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiPkhhbmtlZUpAZW1haWwuY2hvcC5lZHU8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMTk6MjU6MjhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgTm90T25PckFmdGVyPSIyMDE2LTA4LTEwVDE5OjI1OjI4WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT51cm46YXV0aDA6YXZpbGxhY2hsYWI6Q0hPUDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDgtMTBUMTk6MjA6MjhaIiBTZXNzaW9uSW5kZXg9ImlkLXZNVy0zckstdlJlb2V1T2Q1QXRWOEpiLVFRNENtUTB6RzQ1ZlRZSjEiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMjA6MjA6MjhaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+TERBUFNjaGVtZV9HUklOPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=';
       const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile even if the namespace is in response element and assertion is signed', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var encodedSamlResponse = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOng1MDA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm9maWxlczphdHRyaWJ1dGU6WDUwMCIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIgSUQ9InBmeDBiZDdlODQyLTZiZjUtNjE4YS1jOTEwLTJlOTUwNGVlZDgyZiIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmU+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDBiZDdlODQyLTZiZjUtNjE4YS1jOTEwLTJlOTUwNGVlZDgyZiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+cmJPZkR2dkxTVXFmdWpZY1cxYjBMOGFsd2YwPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5NWUhzS0p2eXZrRGVBOHc0ODVQVjRRYlFzeklRb1RlV2IrTGRSa2s5eG9mVmdGMzI1d1BuQk03ckYrTWVaOWZ0MTNuaHVXM0pwbWhLTEpuV2VRenpwREN4SmU4eVcxRHlFL2tIeitGRU1PdDRkNGdLQVVCdVM1ZHloMzA3ZGhPRlluRE9DeDlyL29SbkZDenN1Rlh1STR4UjhEalJWdzl3LzhJQ0NSQ0Z6T0svTFpzZ3BTd215bTFDcm1tK25YcFB1T3prU0psMU1VczlVZEdBeW8wWTBNeVhMS3lidnZaYlR5S0FJZXpRRlNkcjJ3ejRoMXk5SU9KdnBHcmd2M0J1N3pONnRqSUpRTG1FZFZrN3VnWWFRMXJvOWpEMEZqazNOZ0VSRm5EZEVBbW84Y2FsSVM5VlczcFcyZzIwMzIyRGF5a3k2ZmV1bXBKWXpkNFpyQXZvVkE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0icGZ4ZDYzODRjOGUtYmYwYi1kODE5LTlmZDItMjE2M2M1MTJlZjY0IiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDgtMTBUMTk6MjA6MjhaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cDovL2NpZG1mZWQuY2hvcC5lZHUvb2FtL2ZlZDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZT4KICA8ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPgogIDxkczpSZWZlcmVuY2UgVVJJPSIjcGZ4ZDYzODRjOGUtYmYwYi1kODE5LTlmZDItMjE2M2M1MTJlZjY0Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT56SEhGRkI0SkhWallFSnlKWFZrN0M0UUFuTDg9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPk85aS9pb0c5TUNjMUwxM2hqMkoxb3VsaURVK29FOFRFMk9DYWdHanJuM2JaZHBTVDJQM2JKdGFBMXZTWm9sc28xZVRqbjJneWFQM1ZhMno4Q2VScWZoZCtmbHVzS1FKZXRWT0JoZGFMRXU1QnZ3Nm51ZldoTG9sZk5uMVBtR2RFRGRDVU1pWTlOQzFud0laOHN6dkdMNTRDYTl4dmpzbytvY1kvS0drNGpYSHlnSnkyN0lvTFNqMThZSzN2WFBKbUM5N1h6S1VteUxPTUlCaTl3ZitoU1pSa1dUQjVlakRGVWZuekxQL3ZCaHFSVVBZeGFmdjFZU050amJSUE8zSXlub2RzS3F0cVdndmN1ekNHcVAvdFpLWjE4NW14dGxvMnFQUkkxMVk0eDNNZzBidjBIQUJuSXdGcVA0N2EyWFllZU1ZNzFjL0VyNzY2eGpQeklGMFFOQT09PC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRUR6Q0NBdmVnQXdJQkFnSUpBTHI5SHdnclE3R2VNQTBHQ1NxR1NJYjNEUUVCQlFVQU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQWVGdzB4TWpFeU1qa3hOVE13TkRkYUZ3MHhNekF4TWpneE5UTXdORGRhTUdJeEdEQVdCZ05WQkFNVEQyRjFkR2d3TG1GMWRHZ3dMbU52YlRFU01CQUdBMVVFQ2hNSlFYVjBhREFnVEV4RE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LVjJGemFHbHVaM1J2YmpFUU1BNEdBMVVFQnhNSFVtVmtiVzl1WkRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTVppVm1OSGlYTGxkcmdiUzUwT05OT0g3cEoyemc2T2NTTWtZWkdEWkpiT1ovVHF3YXVDNkpPbkk3K3h0a1BKc1FIWlNGSnM0VTBzcmpaS3pEQ21hejJqTEFKRFNoUDJqYVhscmtpMTZuRExQRS8vSUdBZzNCSmd1U21CQ1dwRGJTbTkyVjloU3NFK01oeDZiRGFKaXc4eVErUThpU20wYVRRWnRwNk80SUNNdTAwRVNkaDlOSnFJRUNFTHZQMzFBRFYxWGhqN0lieXlWUERGeE12M29sNUJ5U0U5d3d3T0ZVcS93djdYejlMUmlValV6UE8rTHEzT00zby91Q0RiazdqRDdYckdVdU95ZEFMRDhVTHNYcDRFdURPK25GYmVYQi9pS25kWnludVZLb2tpcnl3bDJuRDJJUDAveW5jZExRWjhCeUl5cVAzRzgyZnEvbDhwN0FzQ0F3RUFBYU9CeHpDQnhEQWRCZ05WSFE0RUZnUVVISTJyVVhlQmpUdjF6QWxsYVBHckhGY0VLMFl3Z1pRR0ExVWRJd1NCakRDQmlZQVVISTJyVVhlQmpUdjF6QWxsYVBHckhGY0VLMGFoWnFSa01HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpJSUpBTHI5SHdnclE3R2VNQXdHQTFVZEV3UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUZCUUFEZ2dFQkFGclhJaEN5NFQ0ZUdyaWtiMFIyd0h2L3VTNTQ4cjNwWnlCVjBDRGJjUndBdGJucEpNdmtHRnFLVnA0cG15b0lEU1ZOSy9qK3NMRXNoQjIwWGZ0ZXpIWnlSSmJDVWJ0S3ZYUTZGc3hvZVpNbE4wSVRZS1Rhb0JaS2hVeHhqOTBvdEFoTkM1OHF3R1VQcXQyTGV3SmhIeUx1Y0trR0oxbVEzYjV4S1o1MzJUb3Vmb3VIOVZMaGlnM0gxS254V28vek1ENktlOGNDazZxTzlodHVoSTA2czNHUUdTMVFXUXRBbW0xN0M2VGZLZ0R3UUZad2hxSFVVWm53S1JIOGdVNk9nWnN2aGdWMUI3SDVtalpjdTU3S01pREJla1U5TUVZMERDVlROM1drbWNUSUk2Njh6THNKcmtOWDZQRWZjazFBTUJiVkU2cEVVS2NXd3EzdWFMdmxBVW89PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWw6U3ViamVjdD48c2FtbDpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI+SGFua2VlSkBlbWFpbC5jaG9wLmVkdTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMjAxNi0wOC0xMFQxOToyNToyOFoiIFJlY2lwaWVudD0iaHR0cHM6Ly9hdmlsbGFjaGxhYi5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2s/Y29ubmVjdGlvbj1DSE9QIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTYtMDgtMTBUMTk6MjA6MjhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMTk6MjU6MjhaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPnVybjphdXRoMDphdmlsbGFjaGxhYjpDSE9QPC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wOC0xMFQxOToyMDoyOFoiIFNlc3Npb25JbmRleD0iaWQtdk1XLTNySy12UmVvZXVPZDVBdFY4SmItUVE0Q21RMHpHNDVmVFlKMSIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAxNi0wOC0xMFQyMDoyMDoyOFoiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj5MREFQU2NoZW1lX0dSSU48L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==';
       const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile even if the namespace is in response element', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var encodedSamlResponse = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOng1MDA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm9maWxlczphdHRyaWJ1dGU6WDUwMCIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIgSUQ9InBmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmU+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+d0ZLLy9YN0dBdzVQQlFIbnRQV2I4T1RoWkVFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT50SWI4WjZPV3ExVDBzd3M2SkZkQWJVUjZGRUJrM0k3TmtYZ2s1d0N0NDJ0TWpQcTM0M2o4YWoxeHdKcXNiWXZMVHZBdHhFZ21vaGd4dmNKN29BRGlxWEJnRFE2SEpOeGUzVTZxM05HTzZRN1hobXRITUZOK2JmK0JsVDdIbGw2TWExMUJmWU5pNnJLblJPcUpUTDZlem01M2pMTm5xazlFbi9HWXdjQUttR0kxQzF4bEo5Y1FEdUh6QTZ3NTdUZXhkQU9YbkJWTWk1MG9Bb0FHOHRhVURXdHBwUXdmdXVDRitEN056NVFvVU5VS0UvRXh0VGpyaUJnMDRSWHY2Z0ZUS3FZYmViNHFETUlxZjZoZ3BWZDF4cm9aaXBHZlFodUhvY2pvVUtRU2ZTUDhCRFlEVFpveFZJaUVCVUhQOFJSSzVYb2Y0NXgwK2ZZajErTzdrZzhWcEE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0iaWQtWS1Sd0hpNlJQOGpNVVI4a3IxRlZ6SHVOdmJ1ck9JZUs2d0dwTmpkLSIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiPkhhbmtlZUpAZW1haWwuY2hvcC5lZHU8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMTk6MjU6MjhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgTm90T25PckFmdGVyPSIyMDE2LTA4LTEwVDE5OjI1OjI4WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT51cm46YXV0aDA6YXZpbGxhY2hsYWI6Q0hPUDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDgtMTBUMTk6MjA6MjhaIiBTZXNzaW9uSW5kZXg9ImlkLXZNVy0zckstdlJlb2V1T2Q1QXRWOEpiLVFRNENtUTB6RzQ1ZlRZSjEiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMjA6MjA6MjhaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+TERBUFNjaGVtZV9HUklOPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=';
       const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile when attribute namespaces are defined in saml response', function(done){
       var encodedSamlResponse = 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiB4bWxuczplbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6eDUwMD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb2ZpbGVzOmF0dHJpYnV0ZTpYNTAwIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9maXJlZ2xhc3MuZXUuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249cHV0bmFtIiBJRD0iaWQtVERVNUw3WnVVU0p0ZWFMZzNXbzZVTEgtN1BId3JqWlZvQzlJQ29haCIgSW5SZXNwb25zZVRvPSJfYTBmNTgwZGYwNGMyZWIwMjE3MzUiIElzc3VlSW5zdGFudD0iMjAxNi0wOC0yOVQxOTozMzoyMloiIFZlcnNpb249IjIuMCI+CiAgPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL29hbS1zdGcucHV0bmFtLmNvbS9vYW0vZmVkPC9zYW1sOklzc3Vlcj4KICA8c2FtbHA6U3RhdHVzPgogICAgPHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPgogIDxzYW1sOkFzc2VydGlvbiBJRD0icGZ4OTlmNmNlMWMtMWE0Ni03Yzk3LTU5MTYtMzRkYTFlZmQ3NGIzIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDgtMjlUMTk6MzM6MjJaIiBWZXJzaW9uPSIyLjAiPgogICAgPHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL29hbS1zdGcucHV0bmFtLmNvbS9vYW0vZmVkPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlPgogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CiAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZng5OWY2Y2UxYy0xYTQ2LTdjOTctNTkxNi0zNGRhMWVmZDc0YjMiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlhmNmEzWTB4d2paZjkyMW5QMjBvT1ZaY09ZUT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+THRxcW5YRUVpRUpvejNDVEJiS0I0M1RZbytudVNacW9iY2Z1bTNhOW0vaHJyVSs2VHRJdWJsblRYQkhsLzU1Y3kwc2pBa2dDL2M3MWpTbU0wQ0owVWNwNjNNdkxoeERnUUdpazBERXNyQnE4UmxHaENDeG9lM0o0elk0OXdmY3ZtUVdXOHlyMG44aG5WcWtNNWV0K3VSTjV2YTNaSjNZdkcwK0NiNEtjNE1CQmgxWDZKUGZhWHQvcFZTQzVTU21VM1FrakpCbUowN2ZobHRJTHJsZVFvYUxmZy84SDFid054M1dETysxd3J3NHo0MEYyTFdnL1huc21ZSzBNZkJKNVFrcHFISUpqU29kbWI5Qy9lS1BCNmRXNE82ZndIS3JaMkFSN2Y5QlhORzN3MnNRbVRzWDFzd0pnd2V3MGpDbzUycjhtV2FHbzlDb3RVN1dZUkwwQXRBPT08L2RzOlNpZ25hdHVyZVZhbHVlPgo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFRHpDQ0F2ZWdBd0lCQWdJSkFMcjlId2dyUTdHZU1BMEdDU3FHU0liM0RRRUJCUVVBTUdJeEdEQVdCZ05WQkFNVEQyRjFkR2d3TG1GMWRHZ3dMbU52YlRFU01CQUdBMVVFQ2hNSlFYVjBhREFnVEV4RE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LVjJGemFHbHVaM1J2YmpFUU1BNEdBMVVFQnhNSFVtVmtiVzl1WkRBZUZ3MHhNakV5TWpreE5UTXdORGRhRncweE16QXhNamd4TlRNd05EZGFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNWmlWbU5IaVhMbGRyZ2JTNTBPTk5PSDdwSjJ6ZzZPY1NNa1laR0RaSmJPWi9UcXdhdUM2Sk9uSTcreHRrUEpzUUhaU0ZKczRVMHNyalpLekRDbWF6MmpMQUpEU2hQMmphWGxya2kxNm5ETFBFLy9JR0FnM0JKZ3VTbUJDV3BEYlNtOTJWOWhTc0UrTWh4NmJEYUppdzh5UStROGlTbTBhVFFadHA2TzRJQ011MDBFU2RoOU5KcUlFQ0VMdlAzMUFEVjFYaGo3SWJ5eVZQREZ4TXYzb2w1QnlTRTl3d3dPRlVxL3d2N1h6OUxSaVVqVXpQTytMcTNPTTNvL3VDRGJrN2pEN1hyR1V1T3lkQUxEOFVMc1hwNEV1RE8rbkZiZVhCL2lLbmRaeW51Vktva2lyeXdsMm5EMklQMC95bmNkTFFaOEJ5SXlxUDNHODJmcS9sOHA3QXNDQXdFQUFhT0J4ekNCeERBZEJnTlZIUTRFRmdRVUhJMnJVWGVCalR2MXpBbGxhUEdySEZjRUswWXdnWlFHQTFVZEl3U0JqRENCaVlBVUhJMnJVWGVCalR2MXpBbGxhUEdySEZjRUswYWhacVJrTUdJeEdEQVdCZ05WQkFNVEQyRjFkR2d3TG1GMWRHZ3dMbU52YlRFU01CQUdBMVVFQ2hNSlFYVjBhREFnVEV4RE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LVjJGemFHbHVaM1J2YmpFUU1BNEdBMVVFQnhNSFVtVmtiVzl1WklJSkFMcjlId2dyUTdHZU1Bd0dBMVVkRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUZyWEloQ3k0VDRlR3Jpa2IwUjJ3SHYvdVM1NDhyM3BaeUJWMENEYmNSd0F0Ym5wSk12a0dGcUtWcDRwbXlvSURTVk5LL2orc0xFc2hCMjBYZnRlekhaeVJKYkNVYnRLdlhRNkZzeG9lWk1sTjBJVFlLVGFvQlpLaFV4eGo5MG90QWhOQzU4cXdHVVBxdDJMZXdKaEh5THVjS2tHSjFtUTNiNXhLWjUzMlRvdWZvdUg5VkxoaWczSDFLbnhXby96TUQ2S2U4Y0NrNnFPOWh0dWhJMDZzM0dRR1MxUVdRdEFtbTE3QzZUZktnRHdRRlp3aHFIVVVabndLUkg4Z1U2T2dac3ZoZ1YxQjdINW1qWmN1NTdLTWlEQmVrVTlNRVkwRENWVE4zV2ttY1RJSTY2OHpMc0pya05YNlBFZmNrMUFNQmJWRTZwRVVLY1d3cTN1YUx2bEFVbz08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1sOlN1YmplY3Q+CiAgICAgIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5EZW1vX1VzZXJAcHV0bmFtLmNvbTwvc2FtbDpOYW1lSUQ+CiAgICAgIDxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj4KICAgICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89Il9hMGY1ODBkZjA0YzJlYjAyMTczNSIgTm90T25PckFmdGVyPSIyMDE2LTA4LTI5VDE5OjM4OjIyWiIgUmVjaXBpZW50PSJodHRwczovL2ZpcmVnbGFzcy5ldS5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2s/Y29ubmVjdGlvbj1wdXRuYW0iLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj4KICAgIDwvc2FtbDpTdWJqZWN0PgogICAgPHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTYtMDgtMjlUMTk6MzM6MjJaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMjlUMTk6Mzg6MjJaIj4KICAgICAgPHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj4KICAgICAgICA8c2FtbDpBdWRpZW5jZT51cm46YXV0aDA6ZmlyZWdsYXNzOnB1dG5hbTwvc2FtbDpBdWRpZW5jZT4KICAgICAgPC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+CiAgICA8L3NhbWw6Q29uZGl0aW9ucz4KICAgIDxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wOC0yOVQxOTozMzoyMVoiIFNlc3Npb25JbmRleD0iaWQtNmhvZ2s4Sm1XcThoSkhld2FWQ05pU05YbXFMMEx2ZndoeVRTOTZDdSIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAxNi0wOC0yOVQyMDozMzoyMloiPgogICAgICA8c2FtbDpBdXRobkNvbnRleHQ+CiAgICAgICAgPHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+CiAgICAgIDwvc2FtbDpBdXRobkNvbnRleHQ+CiAgICA8L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+CiAgICA8c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+CiAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJtYWlsIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4KICAgICAgICA8c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhzaTp0eXBlPSJ4czpzdHJpbmciPkRlbW9fVXNlckBwdXRuYW0uY29tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPgogICAgICA8L3NhbWw6QXR0cmlidXRlPgogICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0ic24iIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPgogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeHNpOnR5cGU9InhzOnN0cmluZyI+VXNlcjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4KICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9ImdpdmVuTmFtZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+CiAgICAgICAgPHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5EZW1vPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPgogICAgICA8L3NhbWw6QXR0cmlidXRlPgogICAgPC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4KICA8L3NhbWw6QXNzZXJ0aW9uPgo8L3NhbWxwOlJlc3BvbnNlPg==';
       const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
       var options = {
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:fireglass:putnam'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile when saml response is encrypted', function(done){
      var encodedSamlResponse = fs.readFileSync(__dirname + '/samples/encoded/samlresponse_encrypted_and_signed.txt').toString();
      const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
      var options = {
        decryptionKey: fs.readFileSync(__dirname + '/test-auth0.key'),
        thumbprint: '119B9E027959CDB7C662CFD075D9E2EF384E445F',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:login0:simplephp'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should accept the signature when the saml response has an embedded XML assertion', function(done){
      var encodedSamlResponse = fs.readFileSync(__dirname + '/samples/encoded/samlresponse_encoded_xml.txt').toString();
      var cert = fs.readFileSync(__dirname + '/test-auth0-2.cer').toString();
      const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
      var options = {
        cert: cert,
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        checkAudience: false,
        checkSPNameQualifier: false
      };
      var samlp = new Samlp(options, new Saml(options));

      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should digest has an extra space', function(done){
      var encodedSamlResponse = fs.readFileSync(__dirname + '/samples/encoded/samlresponse_extraspace.txt').toString();
      var cert = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
      const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
      var options = {
        cert: cert,
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        checkAudience: false,
        checkSPNameQualifier: false
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile for IBM saml response', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var encodedSamlResponse = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9zYWZhcmlqdi5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2s/Y29ubmVjdGlvbj1JQk0tUHJvZCIgSUQ9InBmeDA4NzM0OGQ3LTU0NGUtYjM1OS03MDRlLTA3NjhlZmZjNDllZiIgSW5SZXNwb25zZVRvPSJfMjNkMzQ3YWQzMmFiYmQyODhmYmMiIElzc3VlSW5zdGFudD0iMjAxNi0wOS0wNlQxOToxOTo0NloiIFZlcnNpb249IjIuMCI+PHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ij5odHRwczovL3czaWQuc3NvLmlibS5jb20vYXV0aC9zcHMvc2FtbGlkcC9zYW1sMjA8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmU+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDA4NzM0OGQ3LTU0NGUtYjM1OS03MDRlLTA3NjhlZmZjNDllZiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+bktJSmFnRWhZMG53aldmMmVUTVVweTdCL084PTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5uUW9MdGZsclNhVnBWNkZRRXVPUm8vZHptK3ZOOHFBVTRkakpPeEVYSGpzem1yUVkwVEF2UE5TNzZML2YvbG1aTWJ2a2ZnNVovcFpCbExmcm1zaUJScXE3RUtySHpKcEdVMzllMmZyT2pZOE1hSDk1ZFdoMFN6dEg0cnZOMmNVb3pxT3hGVkhNZmJLVkpUbHRYZ3ZWMWFkYWlTalRpR2lhQURTb1ZUNFAxeWR5QklsZE50N3c4dHlGWU1YMExPa08zMUZGOTNYR0V5WXdSbllGVzBYekxYNEFuRms1amtsa0Y0cGdIbHcvNDNwelJMSmNXMUYra3BMTWJhMTdjZzdYQVZ6d2J5Yzg1R3JMS1czaWpkQ1dFUlcxVERtMWpjd2hDeEZnR2NGcVAwWWFMd0lsZzlDZzA1QTQzV1ZFQnA4VkJSanEray9zNFl1czNLem56V2xxN3c9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0icGZ4YzE0MmE2ZjctZGY4ZC0yMTMxLTVkZDEtOGIyYTI4NWEyMWViIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDktMDZUMTk6MTk6NDZaIiBWZXJzaW9uPSIyLjAiPjxzYW1sOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly93M2lkLnNzby5pYm0uY29tL2F1dGgvc3BzL3NhbWxpZHAvc2FtbDIwPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlPgogIDxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CiAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZnhjMTQyYTZmNy1kZjhkLTIxMzEtNWRkMS04YjJhMjg1YTIxZWIiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlV6VVZTKzZYUlBoS1VLN2N3M2RpaW9mWVNUZz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+dVhYRWpvOENqcWRiRHMyTUVXb29BYnVmdjFockM1QktYdW9ZdVMvOVoxZXFoMXZaZGdWb2dxejJ5enoyWVN0elpvbEI1NXpMOUViSHVISjhqcThGdzZ5RERtN2lnQjJRNnBlajA4RlRya3pCbnQ3NDg1d0tUY1RVSmRFSDd0REpVUjVpYm0yRVNXRlRYaWg3RmlBYjVCczlOQlgra0sxTUpCcEtFUE9ybHFCL0lKYndlMGJRY1FiUzZPU2ZjaVJpUDdWcnczN3hCKzJ0bTVRbGdzeTd1SlhwSGFCK2pFckZUM0VkeWVrYVMrS2dWbUU2Zjk4OUt5OG45YitXMXAxTGJNUUp6NStlVXNhSlZQcXQ2U244U0R1S3QrdXdaV1RNTnRUSjR0WjVoM2t1SEFMOXNwdGhsZGZJN3NVRkF5UnI0S0kyM1lFKzJsSzYycGYvdnVleGFRPT08L2RzOlNpZ25hdHVyZVZhbHVlPgo8ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlFRHpDQ0F2ZWdBd0lCQWdJSkFMcjlId2dyUTdHZU1BMEdDU3FHU0liM0RRRUJCUVVBTUdJeEdEQVdCZ05WQkFNVEQyRjFkR2d3TG1GMWRHZ3dMbU52YlRFU01CQUdBMVVFQ2hNSlFYVjBhREFnVEV4RE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LVjJGemFHbHVaM1J2YmpFUU1BNEdBMVVFQnhNSFVtVmtiVzl1WkRBZUZ3MHhNakV5TWpreE5UTXdORGRhRncweE16QXhNamd4TlRNd05EZGFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNWmlWbU5IaVhMbGRyZ2JTNTBPTk5PSDdwSjJ6ZzZPY1NNa1laR0RaSmJPWi9UcXdhdUM2Sk9uSTcreHRrUEpzUUhaU0ZKczRVMHNyalpLekRDbWF6MmpMQUpEU2hQMmphWGxya2kxNm5ETFBFLy9JR0FnM0JKZ3VTbUJDV3BEYlNtOTJWOWhTc0UrTWh4NmJEYUppdzh5UStROGlTbTBhVFFadHA2TzRJQ011MDBFU2RoOU5KcUlFQ0VMdlAzMUFEVjFYaGo3SWJ5eVZQREZ4TXYzb2w1QnlTRTl3d3dPRlVxL3d2N1h6OUxSaVVqVXpQTytMcTNPTTNvL3VDRGJrN2pEN1hyR1V1T3lkQUxEOFVMc1hwNEV1RE8rbkZiZVhCL2lLbmRaeW51Vktva2lyeXdsMm5EMklQMC95bmNkTFFaOEJ5SXlxUDNHODJmcS9sOHA3QXNDQXdFQUFhT0J4ekNCeERBZEJnTlZIUTRFRmdRVUhJMnJVWGVCalR2MXpBbGxhUEdySEZjRUswWXdnWlFHQTFVZEl3U0JqRENCaVlBVUhJMnJVWGVCalR2MXpBbGxhUEdySEZjRUswYWhacVJrTUdJeEdEQVdCZ05WQkFNVEQyRjFkR2d3TG1GMWRHZ3dMbU52YlRFU01CQUdBMVVFQ2hNSlFYVjBhREFnVEV4RE1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQk1LVjJGemFHbHVaM1J2YmpFUU1BNEdBMVVFQnhNSFVtVmtiVzl1WklJSkFMcjlId2dyUTdHZU1Bd0dBMVVkRXdRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUZyWEloQ3k0VDRlR3Jpa2IwUjJ3SHYvdVM1NDhyM3BaeUJWMENEYmNSd0F0Ym5wSk12a0dGcUtWcDRwbXlvSURTVk5LL2orc0xFc2hCMjBYZnRlekhaeVJKYkNVYnRLdlhRNkZzeG9lWk1sTjBJVFlLVGFvQlpLaFV4eGo5MG90QWhOQzU4cXdHVVBxdDJMZXdKaEh5THVjS2tHSjFtUTNiNXhLWjUzMlRvdWZvdUg5VkxoaWczSDFLbnhXby96TUQ2S2U4Y0NrNnFPOWh0dWhJMDZzM0dRR1MxUVdRdEFtbTE3QzZUZktnRHdRRlp3aHFIVVVabndLUkg4Z1U2T2dac3ZoZ1YxQjdINW1qWmN1NTdLTWlEQmVrVTlNRVkwRENWVE4zV2ttY1RJSTY2OHpMc0pya05YNlBFZmNrMUFNQmJWRTZwRVVLY1d3cTN1YUx2bEFVbz08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIiBOYW1lUXVhbGlmaWVyPSJodHRwczovL3czaWQuc3NvLmlibS5jb20vYXV0aC9zcHMvc2FtbGlkcC9zYW1sMjAiIFNQTmFtZVF1YWxpZmllcj0idXJuOmF1dGgwOnNhZmFyaWp2OklCTS1Qcm9kIj51dWlkNmRkOTc0MzUtMDE1NC0xODZhLTk3MWYtZWUxYzhlZmFiZGRlPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJfMjNkMzQ3YWQzMmFiYmQyODhmYmMiIE5vdE9uT3JBZnRlcj0iMjAxNi0wOS0wNlQxOToyOTo0NloiIFJlY2lwaWVudD0iaHR0cHM6Ly9zYWZhcmlqdi5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2s/Y29ubmVjdGlvbj1JQk0tUHJvZCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTA5LTA2VDE5OjE4OjQ2WiIgTm90T25PckFmdGVyPSIyMDE2LTA5LTA2VDE5OjI5OjQ2WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT51cm46YXV0aDA6c2FmYXJpanY6SUJNLVByb2Q8L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE2LTA5LTA2VDE5OjE5OjQ2WiIgU2Vzc2lvbkluZGV4PSJ1dWlkZWVmZmMwLTAxNTctMWI3Mi1hZmYwLTg5NGFiMDhmODRkOSIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAxNi0wOS0wN1QwODoxOTo0NloiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlIE5hbWU9IkVtYWlsQWRkcmVzcyIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+Y29ybmVsLnBvcGFAcm8uaWJtLmNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJVc2VySUQiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPlk5QzRCTTgyNjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg=='
       const samlResponse = new Buffer(encodedSamlResponse, 'base64').toString();
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        checkDestination: false,
        checkRecipient: false,
        realm: 'urn:auth0:safarijv:IBM-Prod'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });
  });

  it('should reject signature wrapped response', function(done) {
    var encodedSamlResponse = 'PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxzYW1scDpSZXNwb25zZSB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIgeG1sbnM6ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOng1MDA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm9maWxlczphdHRyaWJ1dGU6WDUwMCIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgRGVzdGluYXRpb249Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIgSUQ9InBmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxkczpTaWduYXR1cmU+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI3BmeDJiYTM1MDM4LTdmZmYtZjljMC1jOWJjLTE0NjJlMTQ1NWE3NiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+d0ZLLy9YN0dBdzVQQlFIbnRQV2I4T1RoWkVFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT50SWI4WjZPV3ExVDBzd3M2SkZkQWJVUjZGRUJrM0k3TmtYZ2s1d0N0NDJ0TWpQcTM0M2o4YWoxeHdKcXNiWXZMVHZBdHhFZ21vaGd4dmNKN29BRGlxWEJnRFE2SEpOeGUzVTZxM05HTzZRN1hobXRITUZOK2JmK0JsVDdIbGw2TWExMUJmWU5pNnJLblJPcUpUTDZlem01M2pMTm5xazlFbi9HWXdjQUttR0kxQzF4bEo5Y1FEdUh6QTZ3NTdUZXhkQU9YbkJWTWk1MG9Bb0FHOHRhVURXdHBwUXdmdXVDRitEN056NVFvVU5VS0UvRXh0VGpyaUJnMDRSWHY2Z0ZUS3FZYmViNHFETUlxZjZoZ3BWZDF4cm9aaXBHZlFodUhvY2pvVUtRU2ZTUDhCRFlEVFpveFZJaUVCVUhQOFJSSzVYb2Y0NXgwK2ZZajErTzdrZzhWcEE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiBJRD0iaWQtWS1Sd0hpNlJQOGpNVVI4a3IxRlZ6SHVOdmJ1ck9JZUs2d0dwTmpkLSIgSXNzdWVJbnN0YW50PSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiPmh0dHA6Ly9jaWRtZmVkLmNob3AuZWR1L29hbS9mZWQ8L3NhbWw6SXNzdWVyPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiPkhhbmtlZUpAZW1haWwuY2hvcC5lZHU8L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMTk6MjU6MjhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vYXZpbGxhY2hsYWIuYXV0aDAuY29tL2xvZ2luL2NhbGxiYWNrP2Nvbm5lY3Rpb249Q0hPUCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE2LTA4LTEwVDE5OjIwOjI4WiIgTm90T25PckFmdGVyPSIyMDE2LTA4LTEwVDE5OjI1OjI4WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT51cm46YXV0aDA6YXZpbGxhY2hsYWI6Q0hPUDwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDgtMTBUMTk6MjA6MjhaIiBTZXNzaW9uSW5kZXg9ImlkLXZNVy0zckstdlJlb2V1T2Q1QXRWOEpiLVFRNENtUTB6RzQ1ZlRZSjEiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTYtMDgtMTBUMjA6MjA6MjhaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+TERBUFNjaGVtZV9HUklOPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=';
    var cert = fs.readFileSync(__dirname + '/test-auth0.cer').toString();
    var buffer = new Buffer(encodedSamlResponse, 'base64').toString();
    var xml = buffer.toString();
    //Create version of response without signature

    var stripped = xml
      .replace(/<ds:Signature[\s\S]*ds:Signature>/, "")
      .replace(/<samlp:Response[\s\S]*>/, "")
      .replace(/<\/samlp:Response>/, "")
      .replace(/<saml:Assertion[\s\S]*>/, "")
      .replace(/<\/saml:Assertion>/, "");
    //Create version of response with altered IDs and new username
    var outer = xml
      .replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
      .replace("HankeeJ@email.chop.edu", "admin@esaml2.com");
    //Put stripped version under SubjectConfirmationData of modified version
    var xmlWrapped = outer.replace(/<saml:SubjectConfirmationData[^>]*\/>/, "<saml:SubjectConfirmationData>" + stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', "") + "</saml:SubjectConfirmationData>");

    var newWrap =  new Buffer(xmlWrapped, 'base64').toString();
    var options = {
      cert: cert,
      checkExpiration: false,
      checkDestination: false,
      checkRecipient: false,
      checkAudience: false,
      checkSPNameQualifier: false
    };

    var samlp = new Samlp(options, new Saml(options));
    samlp.validateSamlResponse(xmlWrapped, function (err, profile) {
      expect(err).to.be.ok;
      expect(err.name).to.equals('Error');
      expect(err.message).to.equal('Signature check errors: invalid signature: for uri #pfx2ba35038-7fff-f9c0-c9bc-1462e1455a76 calculated digest is Ayvfyx1bD/XCEn890UHBtv6jkrA= but the xml to validate supplies digest wFK//X7GAw5PBQHntPWb8OThZEE=');
      done();
    });
  });

  describe('getSamlRequestParams', function(){
    before(function(){
      this.samlp = new Samlp({});
    });

    it('should error if the identityProviderUrl is not a string', function(done) {
      var options = {identityProviderUrl: 42};
      this.samlp.getSamlRequestParams(options, function(err, result) {
        expect(err).to.be.an.Error;
        expect(err.message).to.equal('Invalid identity provider URL: 42');
        expect(result).to.not.exist;
        done();
      });
    });

    it('should error if the identityProviderUrl is a string but not a URL', function(done) {
      var options = {identityProviderUrl: 'not a URL'};
      this.samlp.getSamlRequestParams(options, function(err, result) {
        expect(err).to.be.an.Error;
        expect(err.message).to.equal('Invalid identity provider URL: "not a URL"');
        expect(result).to.not.exist;
        done();
      });
    });

    it('should be OK if the identityProviderUrl is a URL', function(done) {
      var relayState = 'foobar';
      var options = {identityProviderUrl: `https://example.com?RelayState=${relayState}`};
      this.samlp.getSamlRequestParams(options, function(err, result) {
        expect(err).to.not.exist;
        expect(result).to.have.property('RelayState', relayState);
        done();
      });
    });

    it('should use providername option', function(done) {
      var samlp = new Samlp({
        identityProviderUrl: server.identityProviderUrl,
        requestTemplate: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="@@ID@@" IssueInstant="@@IssueInstant@@" ProviderName="@@ProviderName@@" ProtocolBinding="@@ProtocolBinding@@" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer></samlp:AuthnRequest>',
        protocol: 'samlp',
        providerName: 'Some name'
      });
      samlp.getSamlRequestParams({}, function(err, params) {
        expect(params).to.have.property('SAMLRequest');
        var SAMLRequest = params.SAMLRequest;

        zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), function (err, buffer) {
          if (err) return done(err);

          var request = buffer.toString();
          var doc = new xmldom.DOMParser().parseFromString(request);

          expect(doc.documentElement.getAttribute('ProviderName'))
            .to.equal('Some name');

          done();
        });
      });
    });

    it('should explode with invalid template', function(done) {
      var samlp = new Samlp({
        identityProviderUrl: server.identityProviderUrl,
        requestTemplate: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="@@ID@@" IssueInstant="@@IssueInstant@@" ProviderName="@@ProviderName@@" ProtocolBinding="@@ProtocolBinding@@" Version="2@@ HI THERE .0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer></samlp:AuthnRequest>@@.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer></samlp:AuthnRequest>',
        protocol: 'samlp',
        providerName: 'Some name'
      });

      samlp.getSamlRequestParams({}, function(err, params) {
        expect(err).not.to.be.null;
        expect(err.message).to.match(/Malformed template/);
        done();
      });
    });


    describe('signing', function () {
      describe('HTTP-POST or HTTP-Redirect without deflate encoding', function () {
        it('should error if the requestTemplate is malformed', function (done) {
          var options = {
            protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            signingKey: {
              key: fs.readFileSync(__dirname + '/test-auth0.key'),
              cert: fs.readFileSync(__dirname + '/test-auth0.pem')
            },
            identityProviderUrl: 'https://example.com?RelayState=foo',
            requestTemplate: '<samlp:AuthnRequest attribute="></samlp:AuthnRequest>'
          };
          this.samlp.getSamlRequestParams(options, function(err, result) {
            expect(err).to.be.an.Error;
            expect(err.message).to.equal('end tag name: samlp:AuthnRequest is not match the current start tagName:undefined');
            expect(result).to.not.exist;
            done();
          });
        });

        it('should place the signature after the issuer', function(done){
          var samlp = new Samlp({
            identityProviderUrl: server.identityProviderUrl,
            requestTemplate: '<samlp:AuthnRequest AssertionConsumerServiceURL="https://dev.qld-gov-dev.auth0.com/login/callback?connection=CIDM-AAL2" Destination="https://uat.identity.qld.gov.au:443/authentication/SSOPOST/metaAlias/idp-07-2017" ForceAuthn="false" ID="@@ID@@" IsPassive="false" IssueInstant="@@IssueInstant@@" ProtocolBinding="@@ProtocolBinding@@" ProviderName="@@ProviderName@@" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer><samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:au:qld:gov:authn:names:SAML:2.0:ac:AAL2</saml:AuthnContextClassRef><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:au:qld:gov:authn:names:SAML:2.0:attributes:FamilyName,MiddleName,GivenName,email,DateOfBirth</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>',
            protocol: 'samlp',
            deflate: false,
            providerName: 'Some name',
            signingKey: {
              key: fs.readFileSync(__dirname + '/test-auth0.key'),
              cert: fs.readFileSync(__dirname + '/test-auth0.pem')
            }
          });

          samlp.getSamlRequestParams({}, function(err, params) {
            if (err){ return done(err); }
            expect(params).to.have.property('SAMLRequest');
            var request = new Buffer(params.SAMLRequest, 'base64').toString();
            var doc = new xmldom.DOMParser().parseFromString(request);

            var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
            expect(issuer[0].nextSibling.nodeName).to.equal('Signature');

            done();
          });
        });
      });
    });
  });

  describe('getSamlRequestUrl', function(){
    before(function(){
      this.samlp = new Samlp({});
    });
    it('should be OK if the identityProviderUrl is a URL', function(done) {
      var options = {identityProviderUrl: 'https://example.com'};
      this.samlp.getSamlRequestUrl(options, function(err, result) {
        expect(err).to.not.exist;
        expect(result).to.match(/^https:\/\/example.com\?SAMLRequest=.*&RelayState=.*/);
        done();
      });
    });
    it('should error if the identityProviderUrl is not a URL', function(done) {
      var options = {identityProviderUrl: null};
      this.samlp.getSamlRequestUrl(options, function(err, result) {
        expect(err).to.be.an.Error;
        expect(err.message).to.equal('Invalid identity provider URL: null');
        expect(result).to.not.exist;
        done();
      });
    });
  });

  describe('getSamlStatus', function(){
    before(function(){
      this.samlp = new Samlp({});
    });

    it('should get result without subcode', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder" /><samlp:StatusMessage>some message</samlp:StatusMessage><samlp:StatusDetail>some details</samlp:StatusDetail></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);

      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.be.undefined;
      expect(result.message).to.equal('some message');
      expect(result.detail).to.equal('some details');
    });

    it('should get result with sucode', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode><samlp:StatusMessage>some message</samlp:StatusMessage><samlp:StatusDetail>some details</samlp:StatusDetail></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).to.equal('some message');
      expect(result.detail).to.equal('some details');
    });

    it('should get result without details', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode><samlp:StatusMessage>some message</samlp:StatusMessage></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).to.equal('some message');
      expect(result.detail).to.be.undefined;
    });

    it('should get result without message', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).be.undefined;
      expect(result.detail).be.undefined;
    });

    it('should get result with status code only', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).be.undefined;
      expect(result.message).be.undefined;
      expect(result.detail).be.undefined;
    });
  });

  describe('deflateAndDecodeResponse', function() {
    it('should decode the SAML response using default settings', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({});
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should decode the SAML response using the defined settings', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({ default_encoding: 'ISO-8859-1' });
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      expect(attributes[0].textContent.trim()).to.equal('test@exåmple.com');
    });

    it('should decode the SAML response using default settings when invalid encoding', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({ default_encoding: 'foo' });
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should get the encoding from the xml tag and decode with the correct encoding', function() {
      const xml = '<?xml version="1.0" encoding="ISO-8859-1"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({});
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      expect(attributes[0].textContent.trim()).to.equal('test@exåmple.com');
    });

    it('should get the encoding from the xml tag and don\'t encode again because it is not valid', function() {
      const xml = '<?xml version="1.0" encoding="foo"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({});
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should get the encoding from the xml tag and decode using utf-8', function() {
      const xml = '<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = zlib.deflateRawSync(new Buffer(xml, 'binary')).toString('base64');
      const samlp = new Samlp({});
      const response = samlp.deflateAndDecodeResponse({ query: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });
  });

  describe('decodeResponse', function(){
    it('should decode the SAML response using default settings', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({});
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should decode the SAML response using the defined settings', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({ default_encoding: 'ISO-8859-1' });
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      expect(attributes[0].textContent.trim()).to.equal('test@exåmple.com');
    });

    it('should decode the SAML response using default settings when invalid encoding', function() {
      const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({ default_encoding: 'foo' });
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should get the encoding from the xml tag and decode with the correct encoding', function() {
      const xml = '<?xml version="1.0" encoding="ISO-8859-1"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({});
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      expect(attributes[0].textContent.trim()).to.equal('test@exåmple.com');
    });

    it('should get the encoding from the xml tag and don\'t encode again because it is not valid', function() {
      const xml = '<?xml version="1.0" encoding="foo"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({});
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });

    it('should get the encoding from the xml tag and decode using utf-8', function() {
      const xml = '<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@exåmple.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>';
      const SAMLResponse = new Buffer(xml, 'binary').toString('base64')
      const samlp = new Samlp({});
      const response = samlp.decodeResponse({ body: { SAMLResponse: SAMLResponse } });
      const doc = new xmldom.DOMParser().parseFromString(response);
      const attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
      expect(attributes.length).to.equal(1);
      expect(attributes[0].getAttribute('Name')).to.equal('mail');
      // wrongly decoded
      expect(attributes[0].textContent.trim()).to.equal('test@ex�mple.com');
    });
  });
});
