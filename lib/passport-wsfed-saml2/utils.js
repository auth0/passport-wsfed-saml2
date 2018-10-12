var xmldom = require('xmldom');
var crypto = require('crypto');

var SamlAssertionParserError = require('./errors/SamlAssertionParserError');
var SamlResponseParserError = require('./errors/SamlResponseParserError');
var WSFederationResultParserError = require('./errors/WSFederationResultParserError');

const CERT_START = "-----BEGIN CERTIFICATE-----\n";
const CERT_END = "\n-----END CERTIFICATE-----\n";

exports.certToPEM = (cert) => CERT_START + cert.match(/.{1,64}/g).join('\n') + CERT_END;

exports.getSamlAssertionVersion = function(samlAssertion){
  if (samlAssertion.getAttribute('MajorVersion') === '1') {
    return '1.1';
  } else if (samlAssertion.getAttribute('Version') === '2.0'){
    return '2.0';
  } else {
    // In this case the version is undefined, or we weren't able to determine it.
    return undefined;
  }

}

exports.parseSamlAssertion = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new SamlAssertionParserError('SAML Assertion should be a valid xml', e);
    }
  }

  return xml;
};

exports.parseSamlResponse = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new SamlResponseParserError('SAMLResponse should be a valid xml', e);
    }
  }

  return xml;
};

exports.parseWsFedResponse = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new WSFederationResultParserError('wresult should be a valid xml', e);
    }
  }

  return xml;
};

exports.getReqUrl = function(req){
  return req.protocol + '://' + (req.get('x-forwarded-host') || req.get('host')) + req.originalUrl;
};

exports.generateUniqueID = function() {
  var uniqueID = crypto.randomBytes(10);
  return uniqueID.toString('hex');
};

exports.getEncoding = function(xml){
  try{
    const response = new xmldom.DOMParser().parseFromString(xml);
    // <?xml version="1.0" encoding="XXXX"?> -> read encoding
    if (response.firstChild && response.firstChild.tagName == 'xml'){
      const regex = /(?:encoding=\")([^\"]*)(?:\")/g;
      const match = regex.exec(response.firstChild.nodeValue);
      // [0] the complete match
      // [1] the specific encoding
      if (match && match.length >= 2){
        // encoding value
        return match[1];
      }
    }
  } catch(e){
    return;
  }
}
