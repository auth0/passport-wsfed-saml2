// credits to: https://github.com/bergie/passport-saml

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');

var SAML = function (options) {
  this.options = options;

  if (!options.cert && !options.thumbprint) {
    throw new Error('You should set either a base64 encoded certificate or the thumbprint of the certificate');
  }
  
  options.signaturePath = options.signaturePath || "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

  if (typeof options.validateSignature === 'undefined') {
    options.validateSignature = true;
  }

  if (typeof options.validateResponse === 'undefined') {
    options.validateResponse = false;
  }
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, cert, thumbprint, callback) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath.SelectNodes(doc, this.options.signaturePath)[0];
  if (!signature)
    return callback(new Error('Signature is missing (xpath: ' + this.options.signaturePath + ')'));

  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      if (thumbprint)  {
        var embeddedSignature = keyInfo[0].getElementsByTagName("X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary');
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

  if (!valid) {
    return callback(new Error('Signature check errors: ' + sig.validationErrors));
  }

  if (cert) {
    return callback(null);
  }

  if (thumbprint) {
    if (this.calculatedThumbprint.toUpperCase() !== thumbprint.toUpperCase()) {
      return callback(new Error('Invalid thumbprint (expected: ' + this.calculatedThumbprint.toUpperCase() + '. actual: ' + thumbprint.toUpperCase() + ')' ));
    }

    return callback();
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
  function getAttributes(samlAssertion) {
    if (samlAssertion['saml:AttributeStatement']) {
      return samlAssertion['saml:AttributeStatement']['saml:Attribute'];
    } else if (samlAssertion.AttributeStatement) {
      return samlAssertion.AttributeStatement.Attribute;
    } else {
      return null;
    }
  }

  function getNameID20(samlAssertion) {
    if (samlAssertion['saml:Subject']) {
      return samlAssertion['saml:Subject']['saml:NameID'];
    } else if (samlAssertion.Subject) {
      return samlAssertion.Subject.NameID;
    } else {
      return null;
    }
  }

  function getNameID11(samlAssertion) {
    if (samlAssertion['saml:AttributeStatement']) {
      return samlAssertion['saml:AttributeStatement']['saml:Subject']['saml:NameIdentifier'];
    } else if (samlAssertion.AttributeStatement) {
      return samlAssertion.AttributeStatement.Subject.NameIdentifier;
    } else {
      return null;
    }
  }

  function getAttributeValue20(attribute) {
    if (attribute['saml:AttributeValue']) {
      return (typeof attribute['saml:AttributeValue']) === "string" ? attribute['saml:AttributeValue'] : attribute['saml:AttributeValue']['#'];
    } else if (attribute.AttributeValue) {
      return (typeof attribute.AttributeValue) === "string" ? attribute.AttributeValue : attribute.AttributeValue['#'];
    } else {
      return null;
    }
  }

  var profile = {};
  var nameId;
  var attributes = getAttributes(samlAssertion);
  if (version === '2.0') {
    if (attributes) {
      attributes  = (attributes instanceof Array) ? attributes : [attributes];
      attributes.forEach(function (attribute) {
        var value = getAttributeValue20(attribute);
        if(typeof value === 'undefined') return;
        profile[attribute['@'].Name] = value;
      });
    }

    nameId = getNameID20(samlAssertion);
    if (nameId) {
      nameId = (typeof nameId) === "string" ? nameId : nameId['#'];
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = nameId;
    }
    
  } else {
    if (attributes) {
      attributes  = (attributes instanceof Array) ? attributes : [attributes];
      attributes.forEach(function (attribute) {
        var value = attribute['saml:AttributeValue'];
        var attributeName = attribute['@'].AttributeNamespace + '/' + attribute['@'].AttributeName;
        if(typeof value === 'undefined') return;
        profile[attributeName] = value;
      });
    }
    
    nameId = getNameID11(samlAssertion);
    if (nameId) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = typeof nameId === 'string' ? nameId : nameId['#'];
    }
  }

  return profile;
};

SAML.prototype.validateSamlResponse = function (samlResponse, callback) {
  var self = this;
  if (!self.options.validateResponse) {
    return callback();
  }

  // validates signature
  self.validateSignature(samlResponse, self.options.cert, self.options.thumbprint, function(err) {
    if (err) return callback(err);

    return callback();
  });
};

SAML.prototype.validateSamlAssertion = function (samlAssertionString, callback) {
  var self = this;
  if (!self.options.validateSignature) {
    return self._parseAssertion(samlAssertionString, callback);
  }

  // validates signature and parse assertion
  self.validateSignature(samlAssertionString, self.options.cert, self.options.thumbprint, function(err) {
    if (err) return callback(err);

    self._parseAssertion(samlAssertionString, callback);
  });
};

SAML.prototype._parseAssertion = function(samlAssertionString, callback) {
  var self = this;
  var parser = new xml2js.Parser();
  parser.parseString(samlAssertionString, function (err, samlAssertion) {

    if (self.options.extractSAMLAssertion){
        samlAssertion = self.options.extractSAMLAssertion(samlAssertion);
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
    var issuer;
    if (samlAssertion['saml:Issuer']) {
      issuer = samlAssertion['saml:Issuer'];
    } else if (samlAssertion.Issuer) {
      issuer = samlAssertion.Issuer;
    } else if (samlAssertion['@'].Issuer) {
      issuer = samlAssertion['@'].Issuer;
    } else {
      issuer = null;
    }

    profile.issuer = issuer;

    if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
      profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
    }

    callback(null, profile);
  });
};

exports.SAML = SAML;
