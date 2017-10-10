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
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
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
