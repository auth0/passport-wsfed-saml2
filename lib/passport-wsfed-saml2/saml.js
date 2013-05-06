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
    if(!options.signaturePath){
        options.signaturePath = "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
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
  var signature = xmlCrypto.xpath.SelectNodes(doc, this.options.signaturePath)[0];
  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
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

SAML.prototype.validateExpiration = function (samlAssertion, version) {
  var notBefore = new Date(version === '2.0' ? samlAssertion.Conditions['@'].NotBefore : samlAssertion['saml:Conditions']['@'].NotBefore);
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew
  
  var notOnOrAfter = new Date(version === '2.0' ? samlAssertion.Conditions['@'].NotOnOrAfter : samlAssertion['saml:Conditions']['@'].NotOnOrAfter);
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

  var now = new Date();

  if (now < notBefore || now > notOnOrAfter)
    return false;

  return true;
};

SAML.prototype.validateAudience = function (samlAssertion, realm, version) {
  var audience = version === '2.0' ? samlAssertion.Conditions.AudienceRestriction.Audience : samlAssertion['saml:Conditions']['saml:AudienceRestrictionCondition']['saml:Audience'];
  return audience === realm;
};

SAML.prototype.parseAttributes = function (samlAssertion, version) {
  var profile = {};
  var attributes;
  if (version === '2.0') {
    attributes = samlAssertion.AttributeStatement.Attribute;
    if (attributes) {
      attributes  = (attributes instanceof Array) ? attributes : [attributes];
      attributes.forEach(function (attribute) {
        var value = attribute.AttributeValue;
        profile[attribute['@'].Name] = value;
      });
    }

    if (samlAssertion.Subject.NameID) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = samlAssertion.Subject.NameID;
    }
    
  } else {
    attributes = samlAssertion['saml:AttributeStatement']['saml:Attribute'];
    if (attributes) {
      attributes  = (attributes instanceof Array) ? attributes : [attributes];
      attributes.forEach(function (attribute) {
        var value = attribute['saml:AttributeValue'];
        var attributeName = attribute['@'].AttributeNamespace + '/' + attribute['@'].AttributeName;
        profile[attributeName] = value;
      });
    }
    
    var nameId = samlAssertion['saml:AttributeStatement']['saml:Subject']['saml:NameIdentifier'];
    if (nameId) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = typeof nameId === 'string' ? nameId : nameId['#'];
    }
  }

  return profile;
};

SAML.prototype.validateResponse = function (samlAssertionString, callback) {
  var self = this;
  
  // Verify signature
  if (!self.validateSignature(samlAssertionString, self.options.cert, self.options.thumbprint)) {
    return callback(new Error('Invalid signature'), null);
  }

  var parser = new xml2js.Parser();
  parser.parseString(samlAssertionString, function (err, samlAssertion) {

    if(self.options.extractSAMLAssertion){
        samlAssertion = self.options.extractSAMLAssertion(samlAssertion)
    }

    var version;
    if (samlAssertion['@'].MajorVersion === '1')
      version = '1.1';
    else if (samlAssertion['@'].Version === '2.0')
      version = '2.0';
    else
      return callback(new Error('SAML Assertion version not supported'), null);

    if (self.options.checkExpiration && !self.validateExpiration(samlAssertion, version)) {
      return callback(new Error('Token has expired.'), null);
    }

    if (self.options.checkAudience && !self.validateAudience(samlAssertion, self.options.realm, version)) {
      return callback(new Error('Audience is invalid. Expected: ' + self.options.realm), null);
    }


    var profile = self.parseAttributes(samlAssertion, version);
    profile.issuer = version === '2.0' ? samlAssertion.Issuer : samlAssertion['@'].Issuer;

    if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
      profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
    }

    callback(null, profile);
  });
};

exports.SAML = SAML;