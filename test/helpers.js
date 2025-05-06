const xmlCrypto = require('xml-crypto');
const xmldom = require('@xmldom/xmldom');
const xpath = require('xpath');

exports.isValidSignature = function(assertion, cert) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  var signature = xpath.select("/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']", doc)[0];
  var sig = new xmlCrypto.SignedXml({ publicCert: cert, getCertFromKeyInfo: () => null, idAttribute: 'AssertionID' });
  sig.loadSignature(signature.toString());
  return sig.checkSignature(assertion);
};

exports.getIssuer = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement.getAttribute('Issuer');
};

exports.getAssertionID = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement.getAttribute('AssertionID');
};

exports.getIssueInstant = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement.getAttribute('IssueInstant');
};

exports.getConditions = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement.getElementsByTagName('saml:Conditions');
};

exports.getAudiences = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement
      .getElementsByTagName('saml:Conditions')[0]
      .getElementsByTagName('saml:AudienceRestrictionCondition')[0]
      .getElementsByTagName('saml:Audience');
};

exports.getAuthenticationStatement = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement
      .getElementsByTagName('saml:AuthenticationStatement')[0];
};

exports.getAttributes = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement
      .getElementsByTagName('saml:Attribute');
};

exports.getNameIdentifier = function(assertion) {
  var doc = new xmldom.DOMParser().parseFromString(assertion, 'text/xml');
  return doc.documentElement
      .getElementsByTagName('saml:NameIdentifier')[0];
};