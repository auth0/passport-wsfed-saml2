// credits to: https://github.com/bergie/passport-saml

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');

var SAML = function (options) {
  this.options = options;

  if (!options.cert && !options.thumbprint) {
    throw new Error('You should set either a base64 encoded certificate or the thumbprint of the certificate');
  }
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert, thumbprint) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>"
    },
    getKey: function (keyInfo) {
      if (thumbprint)  {
        var embeddedSignature = keyInfo[0].getElementsByTagName("X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary')
          shasum.update(der);
          self.calculatedThumbprint = shasum.digest('hex');
    
          return self.certToPEM(base64cer);
        }
      }
      
      return self.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  var valid = sig.checkSignature(xml);

  if (cert) {
    return valid;
  }

  if (thumbprint) {
    return valid && this.calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
  }
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
  if (!self.validateSignature(samlAssertionString, self.options.cert, self.options.thumbprint)) {
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