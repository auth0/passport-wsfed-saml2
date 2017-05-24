var xmldom = require('xmldom');

var SamlAssertionParserError = require('./errors/SamlAssertionParserError');
var SamlResponseParserError = require('./errors/SamlResponseParserError');
var WSFederationResultParserError = require('./errors/WSFederationResultParserError');

exports.parseSamlAssertion = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new SamlAssertionParserError('SAML Assertion should be a valid xml', e);
    }
  }

  return xml;
}

exports.parseSamlResponse = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new SamlResponseParserError('SAMLResponse should be a valid xml', e);
    }
  }

  return xml;
}

exports.parseWsFedResponse = function(xml) {
  if (typeof xml === 'string') {
    try {
      return new xmldom.DOMParser().parseFromString(xml);
    } catch (e) {
      throw new WSFederationResultParserError('wresult should be a valid xml', e);
    }
  }

  return xml;
}
