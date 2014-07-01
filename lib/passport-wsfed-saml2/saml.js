// credits to: https://github.com/bergie/passport-saml

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var xpath = require('xpath');
var cryptiles = require('cryptiles');

var SAML = function (options) {
  this.options = options;

  if (!options.cert && !options.thumbprint) {
    throw new Error('You should set either a base64 encoded certificate or the thumbprint of the certificate');
  }

  this.options.checkExpiration = (typeof this.options.checkExpiration !== 'undefined') ? this.options.checkExpiration : true;
  this.options.checkAudience = (typeof this.options.checkAudience !== 'undefined') ? this.options.checkAudience : true;
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, options, callback) {
  var self = this;
  if (typeof xml === 'string') xml = new xmldom.DOMParser().parseFromString(xml);

  var signaturePath = this.options.signaturePath || options.signaturePath;
  var signature = xpath.select(signaturePath, xml)[0];
  if (!signature)
    return callback(new Error('Signature is missing (xpath: ' + signaturePath + ')'));

  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      if (options.thumbprint)  {
        var embeddedSignature = keyInfo[0].getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary');
          shasum.update(der);
          self.calculatedThumbprint = shasum.digest('hex');
    
          return self.certToPEM(base64cer);
        }
      }
      
      return self.certToPEM(options.cert);
    }
  };
  sig.loadSignature(signature.toString());
  var valid = sig.checkSignature(xml.toString());

  if (!valid) {
    return callback(new Error('Signature check errors: ' + sig.validationErrors));
  }

  if (options.cert) {
    return callback();
  }

  if (options.thumbprint) {
    if (this.calculatedThumbprint.toUpperCase() !== options.thumbprint.toUpperCase()) {
      return callback(new Error('Invalid thumbprint (configured: ' + options.thumbprint.toUpperCase() + '. calculated: ' + this.calculatedThumbprint.toUpperCase() + ')' ));
    }

    return callback();
  }
};

SAML.prototype.validateExpiration = function (samlAssertion, version) {
  var conditions = xpath.select("//*[local-name(.)='Conditions']", samlAssertion);
  if (!conditions || conditions.length === 0) return false;

  var notBefore = new Date(conditions[0].getAttribute('NotBefore'));
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew
  
  var notOnOrAfter = new Date(conditions[0].getAttribute('NotOnOrAfter'));
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew
  var now = new Date();

  if (now < notBefore || now > notOnOrAfter)
    return false;

  return true;
};

SAML.prototype.validateAudience = function (samlAssertion, realm, version) {
  var audience;
  if (version === '2.0') {
    audience = xpath.select("//*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestriction']/*[local-name(.)='Audience']", samlAssertion);
  } else {
    audience = xpath.select("//*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestrictionCondition']/*[local-name(.)='Audience']", samlAssertion);
  }

  if (!audience || audience.length === 0) return false;
  return cryptiles.fixedTimeComparison(audience[0].textContent, realm);
};

SAML.prototype.parseAttributes = function (samlAssertion, version) {
  function getAttributes(samlAssertion) {
    var attributes = xpath.select("//*[local-name(.)='AttributeStatement']/*[local-name(.)='Attribute']", samlAssertion);
    return attributes;
  }

  function getNameID20(samlAssertion) {
    var nameId = xpath.select("//*[local-name(.)='Subject']/*[local-name(.)='NameID']", samlAssertion);
    if (nameId.length === 0) return;
    return nameId[0].textContent;
  }

  function getNameID11(samlAssertion) {
    var nameId = xpath.select("//*[local-name(.)='AttributeStatement']/*[local-name(.)='Subject']/*[local-name(.)='NameIdentifier']", samlAssertion);
    if (nameId.length === 0) return;
    return nameId[0].textContent;
  }

  function getAttributeValues(attribute) {
    if (!attribute || attribute.childNodes.length === 0) return;
    var attributeValues = [];
    for (var i = 0; i<attribute.childNodes.length; i++) {
      attributeValues.push(attribute.childNodes[i].textContent);
    }
    
    if (attributeValues.length === 1) return attributeValues[0];
    
    return attributeValues;
  }

  function getAuthContext20(samlAssertion) {
    var authnContext = xpath.select("//*[local-name(.)='AuthnStatement']/*[local-name(.)='AuthnContext']/*[local-name(.)='AuthnContextClassRef']", samlAssertion);
    if (authnContext.length === 0) return;
    return authnContext[0].textContent;
  }

  var profile = {};
  var nameId;
  var authContext;
  var attributes = getAttributes(samlAssertion);
  if (version === '2.0') {
    for (var index in attributes) {
      var attribute = attributes[index];
      var value = getAttributeValues(attribute);
      profile[attribute.getAttribute('Name')] = value;
    }
    
    nameId = getNameID20(samlAssertion);
    if (nameId) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = nameId;
    }

    authContext = getAuthContext20(samlAssertion);
    if (authContext) {
      profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod'] = authContext;
    }
    
  } else {
    if (attributes) {
      for (var index2 in attributes) {
        var attribute2 = attributes[index2];
        var value2 = getAttributeValues(attribute2);
        profile[attribute2.getAttribute('AttributeNamespace') + '/' + attribute2.getAttribute('AttributeName')] = value2;
      } 
    }
    
    nameId = getNameID11(samlAssertion);
    if (nameId) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = typeof nameId === 'string' ? nameId : nameId['#'];
    }
  }

  return profile;
};

SAML.prototype.validateSamlAssertion = function (samlAssertion, callback) {
  var self = this;

  if (typeof samlAssertion === 'string')
    samlAssertion = new xmldom.DOMParser().parseFromString(samlAssertion);

  self.validateSignature(samlAssertion, { 
    cert: self.options.cert, 
    thumbprint: self.options.thumbprint, 
    signaturePath: "//*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']" }, function(err) {
    if (err) return callback(err);

    self.parseAssertion(samlAssertion, callback);
  });
};

SAML.prototype.parseAssertion = function(samlAssertion, callback) {
  var self = this;
  
  if (self.options.extractSAMLAssertion){
      samlAssertion = self.options.extractSAMLAssertion(samlAssertion);
  }
  
  if (typeof samlAssertion === 'string')
    samlAssertion = new xmldom.DOMParser().parseFromString(samlAssertion).documentElement;
  
  if (!samlAssertion.getAttribute)
    samlAssertion = samlAssertion.documentElement;
  
  var version;
  if (samlAssertion.getAttribute('MajorVersion') === '1')
    version = '1.1';
  else if (samlAssertion.getAttribute('Version') === '2.0')
    version = '2.0';
  else
    return callback(new Error('SAML Assertion version not supported'), null);

  if (self.options.checkExpiration && !self.validateExpiration(samlAssertion, version)) {
    return callback(new Error('assertion has expired.'), null);
  }

  if (self.options.checkAudience && !self.validateAudience(samlAssertion, self.options.realm, version)) {
    return callback(new Error('Audience is invalid. Configured: ' + self.options.realm), null);
  }

  var profile = self.parseAttributes(samlAssertion, version);
  
  var issuer;
  if (version === '2.0') {    
    var issuerNode = xpath.select("//*[local-name(.)='Issuer']", samlAssertion);
    if (issuerNode.length > 0) issuer = issuerNode[0].textContent;
  } else {
    issuer = samlAssertion.getAttribute('Issuer');
  }

  profile.issuer = issuer;

  if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
    profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
  }

  callback(null, profile);
};

exports.SAML = SAML;
