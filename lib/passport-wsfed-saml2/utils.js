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

exports.getReqUrl = function(req) {
  try {
    return req.protocol + '://' + (req.headers['x-forwarded-host'] || req.headers['host']) + req.originalUrl;
  } catch (e) {
    return;
  }
}

exports.generateUniqueID = function() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
}
