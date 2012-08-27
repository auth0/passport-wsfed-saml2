// credits to: https://github.com/bergie/passport-saml

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function (options) {
  this.options = options;
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  }
  return parentElement[elementName];
}

SAML.prototype.validateResponse = function (samlAssertionString, callback) {
  var self = this;
  
  // Verify signature
  if (self.options.cert && !self.validateSignature(samlAssertionString, self.options.cert)) {
    return callback(new Error('Invalid signature'), null);
  }

  var parser = new xml2js.Parser();
  parser.parseString(samlAssertionString, function (err, samlAssertion) {
    
    profile = {};
    profile.issuer = samlAssertion.Issuer;

    var attributeStatement = samlAssertion.AttributeStatement;
    var attributes = attributeStatement.Attribute;
    attributes.forEach(function (attribute) {
      var value = attribute.AttributeValue;
      if (typeof value === 'string') {
        profile[attribute['@'].Name] = value;
        return;
      }
      profile[attribute['@'].Name] = value['#'];
    });

    if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
      profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
    }

    callback(null, profile);
  });
};

exports.SAML = SAML;