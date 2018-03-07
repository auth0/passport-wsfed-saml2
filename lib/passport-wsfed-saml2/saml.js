// credits to: https://github.com/bergie/passport-saml

var crypto    = require('crypto');
var cryptiles = require('cryptiles');
var xpath     = require('xpath');
var xmlCrypto = require('xml-crypto');
var EventEmitter = require('events');

var utils = require('./utils');
var ELEMENT_NODE = 1;

var SAML = function (options) {
  this.options = options || {};

  if (this.options.thumbprint) {
    this.options.thumbprints = (this.options.thumbprints || []).concat([this.options.thumbprint]);
  }

  if (!this.options.cert && (!this.options.thumbprints || this.options.thumbprints.length === 0)) {
    throw new Error('You should set either a base64 encoded certificate or the thumbprints of the signing certificates');
  }

  this.options.checkExpiration = (typeof this.options.checkExpiration !== 'undefined') ? this.options.checkExpiration : true;
  this.options.checkAudience = (typeof this.options.checkAudience !== 'undefined') ? this.options.checkAudience : true;
  this.options.checkRecipient = (typeof this.options.checkRecipient !== 'undefined') ? this.options.checkRecipient : true;
  this.options.checkNameQualifier = (typeof this.options.checkNameQualifier !== 'undefined') ? this.options.checkNameQualifier : true;
  this.options.checkSPNameQualifier = (typeof this.options.checkSPNameQualifier !== 'undefined') ? this.options.checkSPNameQualifier : true;
  this.eventEmitter = this.options.eventEmitter || new EventEmitter();
};

SAML.prototype.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};

SAML.prototype.validateSignature = function (xml, options, callback) {
  var self = this;
  xml = utils.parseSamlResponse(xml);

  var signaturePath = this.options.signaturePath || options.signaturePath;
  var signatures = xpath.select(signaturePath, xml);
  if (signatures.length === 0) {
    return callback(new Error('Signature is missing (xpath: ' + signaturePath + ')'));
  } else if (signatures.length > 1) {
    return callback(new Error('Signature was found more than one time (xpath: ' + signaturePath + ')'));
  }
  var signature = signatures[0];

  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
  sig.keyInfoProvider = {
    getKeyInfo: function (key) {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {

      //If there's no embedded signing cert, use the configured cert through options
      if(!keyInfo || keyInfo.length===0){
        if(!options.cert) throw new Error('options.cert must be specified for SAMLResponses with no embedded signing certificate');
        return self.certToPEM(options.cert);
      }

      //If there's an embedded signature and thumprints are provided check that
      if (options.thumbprints && options.thumbprints.length > 0)  {
        var embeddedSignature = keyInfo[0].getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary');
          shasum.update(der, 'latin1');
          self.calculatedThumbprint = shasum.digest('hex');

          // using embedded cert, so options.cert is not used anymore
          delete options.cert;
          return self.certToPEM(base64cer);
        }
      }

      // If there's an embedded signature, but no thumprints are supplied, use options.cert
      // either options.cert or options.thumbprints must be specified so at this point there
      // must be an options.cert
      return self.certToPEM(options.cert);
    }
  };

  var valid;

  try {
    sig.loadSignature(signature);
    valid = sig.checkSignature(xml.toString());
  } catch (e) {
    if (e.message === 'PEM_read_bio_PUBKEY failed') {
      return callback(new Error('The signing certificate is invalid (' + e.message + ')'));
    }

    return callback(e);
  }

  if (!valid) {
    return callback(new Error('Signature check errors: ' + sig.validationErrors));
  }

  if (options.cert) {
    return callback();
  }

  if (options.thumbprints) {

    var valid_thumbprint = options.thumbprints.some(function (thumbprint) {
      return self.calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
    });

    if (!valid_thumbprint) {
      return callback(new Error('Invalid thumbprint (configured: ' + options.thumbprints.join(', ').toUpperCase() + '. calculated: ' + this.calculatedThumbprint.toUpperCase() + ')' ));
    }

    return callback();
  }
};

SAML.prototype.validateExpiration = function (samlAssertion, version) {
  var conditions = xpath.select(".//*[local-name(.)='Conditions']", samlAssertion);
  if (!conditions || conditions.length === 0) return true;

  var notBefore = new Date(conditions[0].getAttribute('NotBefore'));
  notBefore = notBefore.setMinutes(notBefore.getMinutes() - 5); // 5 minutes clock skew

  var notOnOrAfter = new Date(conditions[0].getAttribute('NotOnOrAfter'));
  notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 5); // 5 minutes clock skew
  var now = new Date();

  if (now < notBefore || now > notOnOrAfter)
    return false;

  return true;
};

SAML.prototype.validateAudience = function (samlAssertion, realm, version) {
  var audience;
  if (version === '2.0') {
    audience = xpath.select(".//*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestriction']/*[local-name(.)='Audience']", samlAssertion);
  } else {
    audience = xpath.select(".//*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestrictionCondition']/*[local-name(.)='Audience']", samlAssertion);
  }

  if (!audience || audience.length === 0) return false;
  return cryptiles.fixedTimeComparison(audience[0].textContent, realm);
};

SAML.prototype.validateNameQualifier = function (samlAssertion, issuer) {
  var nameID = getNameID20(samlAssertion);
  // NameQualifier is optional. Only validate if exists
  if (!nameID || !nameID.Format || !nameID.NameQualifier) return true;

  if ([
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    ].indexOf(nameID.Format) == -1){
      // Ignore validation if the format is not persistent or transient
      return true;
  }

  return nameID.NameQualifier === issuer
};

SAML.prototype.validateSPNameQualifier = function (samlAssertion, audience) {
  var nameID = getNameID20(samlAssertion);
  // SPNameQualifier is optional. Only validate if exists
  if (!nameID || !nameID.Format || !nameID.SPNameQualifier) return true;

  if ([
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    ].indexOf(nameID.Format) == -1){
      // Ignore validation if the format is not persistent or transient
      return true;
  }

  return nameID.SPNameQualifier === audience
};

// https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
// Page 19 of 91
// Recipient [Optional]
// A URI specifying the entity or location to which an attesting entity can present the assertion. For
// example, this attribute might indicate that the assertion must be delivered to a particular network
// endpoint in order to prevent an intermediary from redirecting it someplace else.
SAML.prototype.validateRecipient = function(samlAssertion, recipientUrl){
  var subjectConfirmationData = xpath.select(".//*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']", samlAssertion);

  // subjectConfirmationData is optional in the spec. Only validate if the assertion contains a recipient
  if (!subjectConfirmationData || subjectConfirmationData.length === 0){
    return true;
  }

  var recipient = subjectConfirmationData[0].getAttribute('Recipient');

  var valid = !recipient || recipient === recipientUrl;

  if (!valid){
    this.eventEmitter.emit('recipientValidationFailed', {
       configuredRecipient: recipientUrl,
       assertionRecipient: recipient
     });
  }

  return valid;
};

SAML.prototype.parseAttributes = function (samlAssertion, version) {
  function getAttributes(samlAssertion) {
    var attributes = xpath.select(".//*[local-name(.)='AttributeStatement']/*[local-name(.)='Attribute']", samlAssertion);
    return attributes;
  }

  function getSessionIndex(samlAssertion) {
    var authnStatement = xpath.select(".//*[local-name(.)='AuthnStatement']", samlAssertion);
    var sessionIndex = authnStatement.length > 0 && authnStatement[0].attributes.length > 0 ?
                    authnStatement[0].getAttribute('SessionIndex') : undefined;
    return sessionIndex || undefined;
  }

  function getNameID11(samlAssertion) {
    var nameId = xpath.select(".//*[local-name(.)='AuthenticationStatement']/*[local-name(.)='Subject']/*[local-name(.)='NameIdentifier']", samlAssertion);

    if (nameId.length === 0) {
      // only for backward compatibility with adfs
      nameId = xpath.select(".//*[local-name(.)='AttributeStatement']/*[local-name(.)='Subject']/*[local-name(.)='NameIdentifier']", samlAssertion);
      if (nameId.length === 0) return;
    }

    return nameId[0].textContent;
  }

  function getAttributeValues(attribute) {
    if (!attribute || attribute.childNodes.length === 0) return;
    var attributeValues = [];
    for (var i = 0; i<attribute.childNodes.length; i++) {
      if (attribute.childNodes[i].nodeType !== ELEMENT_NODE) continue;
      attributeValues.push(attribute.childNodes[i].textContent);
    }

    if (attributeValues.length === 1) return attributeValues[0];

    return attributeValues;
  }

  function getAuthContext20(samlAssertion) {
    var authnContext = xpath.select(".//*[local-name(.)='AuthnStatement']/*[local-name(.)='AuthnContext']/*[local-name(.)='AuthnContextClassRef']", samlAssertion);
    if (authnContext.length === 0) return;
    return authnContext[0].textContent;
  }

  var profile = {};
  var nameId;
  var authContext;
  var attributes = getAttributes(samlAssertion);
  profile.sessionIndex = getSessionIndex(samlAssertion);
  if (version === '2.0') {
    for (var index in attributes) {
      var attribute = attributes[index];
      var value = getAttributeValues(attribute);
      profile[attribute.getAttribute('Name')] = value;
    }

    nameId = getNameID20(samlAssertion);

    if (nameId) {
      profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = nameId.value;
      if(Object.keys(nameId).length > 1) {
        profile['nameIdAttributes'] = nameId;
      }
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

  samlAssertion = utils.parseSamlResponse(samlAssertion);

  self.validateSignature(samlAssertion.toString(), {
    cert: self.options.cert,
    thumbprints: self.options.thumbprints,
    signaturePath: "/*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']" }, function(err) {
    if (err) return callback(err);

    self.parseAssertion(samlAssertion, callback);
  });
};

SAML.prototype.parseAssertion = function(samlAssertion, callback) {
  var self = this;
  if (self.options.extractSAMLAssertion){
    samlAssertion = self.options.extractSAMLAssertion(samlAssertion);
  }

  samlAssertion = utils.parseSamlResponse(samlAssertion);

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

  if (!self.validateRecipient(samlAssertion, self.options.recipientUrl)) {
    if (self.options.checkRecipient){
      return callback(new Error('Recipient is invalid. Configured: ' + self.options.recipientUrl), null);
    }
  }

  var profile = self.parseAttributes(samlAssertion, version);

  var issuer;
  if (version === '2.0') {
    var issuerNode = xpath.select(".//*[local-name(.)='Issuer']", samlAssertion);
    if (issuerNode.length > 0) issuer = issuerNode[0].textContent;
  } else {
    issuer = samlAssertion.getAttribute('Issuer');
  }


  this.eventEmitter.emit('parseAssertion', {
      issuer: issuer,
      version: version,
    });

  profile.issuer = issuer;

  // Validate the name qualifier in the NameID element if found with the audience
  if (self.options.checkNameQualifier && !self.validateNameQualifier(samlAssertion, issuer)){
    return callback(new Error('NameQualifier attribute in the NameID element does not match ' + issuer), null);
  }

  // Validate the SP name qualifier in the NameID element if found with the issuer
  if (self.options.checkSPNameQualifier && !self.validateSPNameQualifier(samlAssertion, self.options.realm)){
    return callback(new Error('SPNameQualifier attribute in the NameID element does not match ' + self.options.realm), null);
  }

  if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
    profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
  }

  callback(null, profile);
};

function getNameID20(samlAssertion) {
  var nameId = xpath.select(".//*[local-name(.)='Subject']/*[local-name(.)='NameID']", samlAssertion);
  if (nameId.length === 0) return;
  var element = nameId[0];
  var result = {
    value: element.textContent,
  };

  ['NameQualifier',
    'SPNameQualifier',
    'Format',
    'SPProvidedID'].forEach(function(key) {
    var value = element.getAttribute(key);
    if (!value) return;
    result[key] = element.getAttribute(key);
  });

  return result;
}

exports.SAML = SAML;
