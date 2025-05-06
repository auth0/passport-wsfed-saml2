const crypto    = require('crypto');
const xpath     = require('xpath');
const xmlCrypto = require('xml-crypto');
const EventEmitter = require('events');
const forge = require('node-forge');
const utils = require('./utils');
const xmldom = require('@xmldom/xmldom');

const ELEMENT_NODE = 1;

const domParser = new xmldom.DOMParser();

const getAuthContext20 = (samlAssertion) => {
  const authnContext = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='AuthnStatement']/*[local-name(.)='AuthnContext']/*[local-name(.)='AuthnContextClassRef']", samlAssertion);
  if (authnContext.length === 0) {
    return;
  }
  return authnContext[0].textContent;
};

const getAttributeValues = (attribute) => {
  if (!attribute || attribute.childNodes.length === 0) {
    return;
  }
  const attributeValues = [];
  for (let i = 0; i < attribute.childNodes.length; i++) {
    if (attribute.childNodes[i].nodeType !== ELEMENT_NODE) {
      continue;
    }
    attributeValues.push(attribute.childNodes[i].textContent);
  }

  if (attributeValues.length === 1) {
    return attributeValues[0];
  }

  return attributeValues;
};

const getSessionIndex = (samlAssertion) => {
  const authnStatement = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='AuthnStatement']", samlAssertion);
  const sessionIndex = authnStatement.length > 0 && authnStatement[0].attributes.length > 0 ?
      authnStatement[0].getAttribute('SessionIndex') : undefined;
  return sessionIndex || undefined;
};

const getAttributes = (samlAssertion) => {
  return xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='AttributeStatement']/*[local-name(.)='Attribute']", samlAssertion);
};

const getNameID11 = (samlAssertion) => {
  let nameId = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='AuthenticationStatement']/*[local-name(.)='Subject']/*[local-name(.)='NameIdentifier']", samlAssertion);

  if (nameId.length === 0) {
    // only for backward compatibility with adfs
    nameId = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='AttributeStatement']/*[local-name(.)='Subject']/*[local-name(.)='NameIdentifier']", samlAssertion);
    if (nameId.length === 0) {
      return;
    }
  }

  return nameId[0].textContent;
};

const getNameID20 = (samlAssertion) => {
  const nameId = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Subject']/*[local-name(.)='NameID']", samlAssertion);
  if (nameId.length === 0) {
    return;
  }
  const element = nameId[0];
  const result = {
    value: element.textContent,
  };

  [
    'NameQualifier',
    'SPNameQualifier',
    'Format',
    'SPProvidedID'
  ].forEach(function(key) {
    const value = element.getAttribute(key);
    if (!value) {
      return;
    }
    result[key] = element.getAttribute(key);
  });

  return result;
};

function getKeyFn(options) {
  return function (keyInfo) {
    //If there's no embedded signing cert, use the configured cert through options
    if (!keyInfo || keyInfo.length === 0 ){
      if (!options.cert) {
        throw new Error('options.cert must be specified for SAMLResponses with no embedded signing certificate');
      }
      return utils.certToPEM(options.cert);
    }

    //If there's an embedded signature and thumbprints are provided check that
    if (options.thumbprints && options.thumbprints.length > 0)  {
      const embeddedSignature = keyInfo.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');
      if (embeddedSignature.length > 0) {
        const base64cer = embeddedSignature[0].firstChild.toString();
        const shasum = crypto.createHash('sha1');
        const der = new Buffer(base64cer, 'base64').toString('binary');
        shasum.update(der, 'latin1');
        const calculatedThumbprint = shasum.digest('hex').toUpperCase();
        const validThumbprint = options.thumbprints.some(function (thumbprint) {
          return calculatedThumbprint === thumbprint.toUpperCase();
        });

        if (!validThumbprint) {
          throw new Error('Invalid thumbprint (configured: ' + options.thumbprints.join(', ').toUpperCase() + '. calculated: ' + calculatedThumbprint + ')' );
        }
        // using embedded cert, so options.cert is not used anymore
        delete options.cert;
        return utils.certToPEM(base64cer);
      }
    }

    // If there's an embedded signature, but no thumbprints are supplied, use options.cert
    // either options.cert or options.thumbprints must be specified so at this point there
    // must be an options.cert
    return utils.certToPEM(options.cert);
  }
}

class SAML {
  constructor(options) {
    this.options = options || {};

    if (this.options.thumbprint) {
      this.options.thumbprints = (this.options.thumbprints || []).concat([this.options.thumbprint]);
    }

    if (!this.options.cert && (!this.options.thumbprints || this.options.thumbprints.length === 0)) {
      throw new Error('You should set either a base64 encoded certificate or the thumbprints of the signing certificates');
    }

    this.options.checkExpiration = (typeof this.options.checkExpiration !== 'undefined') ? this.options.checkExpiration : true;
    // Note! It would be best to set this to true. But it's defaulting to false so as not to break login for expired certs.
    this.options.checkCertExpiration = (typeof this.options.checkCertExpiration !== 'undefined') ? this.options.checkCertExpiration : false;
    // clockskew in minutes
    this.options.clockSkew = (typeof this.options.clockSkew === 'number' && this.options.clockSkew >= 0) ? this.options.clockSkew : 3;
    this.options.checkAudience = (typeof this.options.checkAudience !== 'undefined') ? this.options.checkAudience : true;
    this.options.checkRecipient = (typeof this.options.checkRecipient !== 'undefined') ? this.options.checkRecipient : true;
    this.options.checkNameQualifier = (typeof this.options.checkNameQualifier !== 'undefined') ? this.options.checkNameQualifier : true;
    this.options.checkSPNameQualifier = (typeof this.options.checkSPNameQualifier !== 'undefined') ? this.options.checkSPNameQualifier : true;
    this.eventEmitter = this.options.eventEmitter || new EventEmitter();
    this.getUseTextContentDigestValue = options.getUseTextContentDigestValue;

    this.parser = domParser;
  }

  buildSignatureValidator (options) {
    const sig = new xmlCrypto.SignedXml({ idAttribute: 'AssertionID', getCertFromKeyInfo: getKeyFn(options) });
    return sig;
  }

  validateSignature (str, options, callback) {
    const xml = utils.parseSamlResponse(str, this.parser);

    const signaturePath = this.options.signaturePath || options.signaturePath;
    const signatures = xpath.select(signaturePath, xml);
    if (signatures.length === 0) {
      return callback(new Error('Signature is missing (xpath: ' + signaturePath + ')'));
    } else if (signatures.length > 1) {
      return callback(new Error('Signature was found more than one time (xpath: ' + signaturePath + ')'));
    }
    const signature = signatures[0];

    let valid;
    const opts = Object.assign({}, options, { cert: this.options.cert, thumbprints: this.options.thumbprints });
    const sig = this.buildSignatureValidator(opts);
    try {
      sig.loadSignature(signature);
      valid = sig.checkSignature(utils.crlf2lf(str));

      // TODO: this shouldn't be done until we have determined its completely valid, it should happen in `parseAssertion`
      if (!this.extractAndValidateCertExpiration(xml, this.options.cert) && this.options.checkCertExpiration) {
        return callback(new Error('The signing certificate is not currently valid.'), null);
      }
    } catch (e) {
      if (e.message === 'PEM_read_bio_PUBKEY failed') {
        return callback(new Error('The signing certificate is invalid (' + e.message + ')'));
      }
      if (e.opensslErrorStack !== undefined) {
        const err = new Error(`The signing certificate is invalid (${e.opensslErrorStack.join(', ')})`);
        err.originalError = e;

        return callback(err);
      }

      return callback(e);
    }

    if (!valid) {
      return callback(new Error('Signature check errors: ' + sig.references[0].validationError.message));
    }

    if (!sig.getSignedReferences().length) {
      return callback(new Error('Could not validate Signature(s)'));
    }

    return callback(null, sig.getSignedReferences()[0]);
  }

  extractAndValidateCertExpiration (validatedSamlAssertion, optionsCert) {
    // This accepts a validated SAML assertion and checks current time against the valid cert dates
    const certNodes = validatedSamlAssertion.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');

    const cert = certNodes.length > 0 ? certNodes[0].textContent : optionsCert;

    if (!cert) { return false; }

    const parsedCert = forge.pki.certificateFromPem(utils.certToPEM(cert));

    const nowDate = new Date();

    // true if current date is before expiry AND after cert start date
    if ( ! (nowDate > parsedCert.validity.notBefore && nowDate < parsedCert.validity.notAfter)) {
      this.eventEmitter.emit('certificateExpirationValidationFailed', {});
      return false;
    }

    return true;
  }

  validateExpiration (samlAssertion) {
    const conditions = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Conditions']", samlAssertion);
    if (!conditions || conditions.length === 0) {
      return true;
    }

    const condition = conditions[0];
    const notBefore = condition.getAttribute('NotBefore');
    const notOnOrAfter = condition.getAttribute('NotOnOrAfter');

    // no expiration defined.
    if (!notBefore && !notOnOrAfter) {
      return true
    }

    const now = new Date();

    // ideally, the parameters provided to new Date would validate that produce a valid date object, but for the
    // rollout we will maintain the same behavior we currently have to prevent introducing additional breaking changes

    if (notBefore) {
      const notBeforeDate = new Date(notBefore);
      notBeforeDate.setMinutes(notBeforeDate.getMinutes() - this.options.clockSkew);
      if (now < notBefore) {
        return false;
      }
    }

    if (notOnOrAfter) {
      const notOnOrAfterDate = new Date(notOnOrAfter);
      notOnOrAfterDate.setMinutes(notOnOrAfterDate.getMinutes() + this.options.clockSkew);
      if (now > notOnOrAfterDate) {
        return false;
      }
    }

    return true;
  }

  validateAudience (samlAssertion, realm, version) {
    let audience;
    if (version === '2.0') {
      audience = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestriction']/*[local-name(.)='Audience']", samlAssertion);
    } else {
      audience = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Conditions']/*[local-name(.)='AudienceRestrictionCondition']/*[local-name(.)='Audience']", samlAssertion);
    }

    if (!audience || audience.length === 0) {return false;}
    return utils.stringCompare(audience[0].textContent, realm);
  }

  validateNameQualifier (samlAssertion, issuer) {
    const nameID = getNameID20(samlAssertion);
    // NameQualifier is optional. Only validate if exists
    if (!nameID || !nameID.Format || !nameID.NameQualifier) {
      return true;
    }

    if ([
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    ].indexOf(nameID.Format) === -1){
      // Ignore validation if the format is not persistent or transient
      return true;
    }

    return nameID.NameQualifier === issuer;
  }

  validateSPNameQualifier (samlAssertion, audience) {
    const nameID = getNameID20(samlAssertion);
    // SPNameQualifier is optional. Only validate if exists
    if (!nameID || !nameID.Format || !nameID.SPNameQualifier) {return true;}

    if ([
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    ].indexOf(nameID.Format) === -1){
      // Ignore validation if the format is not persistent or transient
      return true;
    }

    return nameID.SPNameQualifier === audience;
  }

  // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
  // Page 19 of 91
  // Recipient [Optional]
  // A URI specifying the entity or location to which an attesting entity can present the assertion. For
  // example, this attribute might indicate that the assertion must be delivered to a particular network
  // endpoint in order to prevent an intermediary from redirecting it someplace else.
  validateRecipient (samlAssertion, recipientUrl){
    const subjectConfirmationData = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']", samlAssertion);

    // subjectConfirmationData is optional in the spec. Only validate if the assertion contains a recipient
    if (!subjectConfirmationData || subjectConfirmationData.length === 0){
      return true;
    }

    const recipient = subjectConfirmationData[0].getAttribute('Recipient');

    const valid = !recipient || recipient === recipientUrl;

    if (!valid){
      this.eventEmitter.emit('recipientValidationFailed', {
        configuredRecipient: recipientUrl,
        assertionRecipient: recipient
      });
    }

    return valid;
  }

  parseAttributes (samlAssertion, version) {
    const profile = {};
    const attributes = getAttributes(samlAssertion);
    profile.sessionIndex = getSessionIndex(samlAssertion);
    if (version === '2.0') {
      for (let index in attributes) {
        const attribute = attributes[index];
        profile[attribute.getAttribute('Name')] = getAttributeValues(attribute);
      }

      const nameId = getNameID20(samlAssertion);

      if (nameId) {
        profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = nameId.value;
        if(Object.keys(nameId).length > 1) {
          profile['nameIdAttributes'] = nameId;
        }
      }

      const authContext = getAuthContext20(samlAssertion);
      if (authContext) {
        profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod'] = authContext;
      }
    } else {
      if (attributes) {
        for (let index in attributes) {
          const attribute = attributes[index];
          profile[attribute.getAttribute('AttributeNamespace') + '/' + attribute.getAttribute('AttributeName')] = getAttributeValues(attribute);
        }
      }

      const nameId = getNameID11(samlAssertion);
      if (nameId) {
        profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'] = typeof nameId === 'string' ? nameId : nameId['#'];
      }
    }

    return profile;
  }

  validateSamlAssertion (samlAssertionStr, options, callback) {
    this.validateSignature(samlAssertionStr, {
      meta: options.meta,
      signaturePath: "//*[local-name(.)='Assertion'][1]/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']" }, (err, signed) => {
      if (err) {return callback(err);}

      this.parseAssertion(signed, callback);
    });
  }

  parseAssertion (samlAssertion, callback) {
    if (this.options.extractSAMLAssertion){
      samlAssertion = this.options.extractSAMLAssertion(samlAssertion);
    }

    samlAssertion = utils.parseSamlAssertion(samlAssertion, this.parser);

    if (!samlAssertion.getAttribute) {
      samlAssertion = samlAssertion.documentElement;
    }

    if (samlAssertion.localName !== 'Assertion') {
      return callback(new Error('saml response does not contain an Assertion element'));
    }

    const version = utils.getSamlAssertionVersion(samlAssertion);
    if (!version){
      // Note that this assumes any version returned by getSamlAssertionVersion is supported.
      return callback(new Error('SAML Assertion version not supported, or not defined'), null);
    }

    if (this.options.checkExpiration && !this.validateExpiration(samlAssertion, version)) {
      return callback(new Error('assertion has expired.'), null);
    }

    if (this.options.checkAudience && !this.validateAudience(samlAssertion, this.options.realm, version)) {
      return callback(new Error('Audience is invalid. Configured: ' + this.options.realm), null);
    }

    if (!this.validateRecipient(samlAssertion, this.options.recipientUrl)) {
      if (this.options.checkRecipient){
        return callback(new Error('Recipient is invalid. Configured: ' + this.options.recipientUrl), null);
      }
    }

    const profile = this.parseAttributes(samlAssertion, version);

    let issuer;
    if (version === '2.0') {
      const issuerNode = xpath.select("//*[local-name(.)='Assertion'][1]/*[local-name(.)='Issuer']", samlAssertion);
      if (issuerNode.length > 0) {
        issuer = issuerNode[0].textContent;
      }
    } else {
      issuer = samlAssertion.getAttribute('Issuer');
    }

    this.eventEmitter.emit('parseAssertion', {
      issuer: issuer,
      version: version,
    });

    profile.issuer = issuer;

    // Validate the name qualifier in the NameID element if found with the audience
    if (this.options.checkNameQualifier && !this.validateNameQualifier(samlAssertion, issuer)) {
      return callback(new Error('NameQualifier attribute in the NameID element does not match ' + issuer), null);
    }

    // Validate the SP name qualifier in the NameID element if found with the issuer
    if (this.options.checkSPNameQualifier && !this.validateSPNameQualifier(samlAssertion, this.options.realm)){
      return callback(new Error('SPNameQualifier attribute in the NameID element does not match ' + this.options.realm), null);
    }

    if (!profile.email && profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
      profile.email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
    }

    return callback(null, profile);
  }
}

exports.SAML = SAML;