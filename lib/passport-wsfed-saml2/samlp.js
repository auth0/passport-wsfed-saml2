var xmldom = require('xmldom');
var qs = require('querystring');
var zlib = require('zlib');
var xtend = require('xtend');
var templates = require('./templates');

var Samlp = module.exports = function Samlp (options) {
  this.options = options || {};
  this.options.protocolBinding = options.protocolBinding || 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
  if (typeof options.deflate === 'undefined') this.options.deflate = true;

};

Samlp.prototype = {
  getSamlRequestUrl: function (opts, callback) {
    var options = xtend(opts || {}, this.options);

    var SAMLRequest = templates.samlrequest({
      ID:               '_' + generateUniqueID(),
      IssueInstant:     generateInstant(),
      Destination:      options.identityProviderUrl,
      Issuer:           options.realm,
      ProtocolBinding:  options.protocolBinding,
      AssertionConsumerServiceURL: options.callback
    }).replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();

    if (options.deflate) {
      zlib.deflateRaw(new Buffer(SAMLRequest), function(err, buffer) {
        if (err) return callback(err);

        callback(null, buildUrl(buffer));  
      });
    } else {
      callback(null, buildUrl(new Buffer(SAMLRequest)));  
    }
    
    function buildUrl(buffer) {
      var url = options.identityProviderUrl + '?' + qs.encode( { SAMLRequest: buffer.toString('base64'), RelayState: options.RelayState || '' });
      return url;
    }
  },

  decodeResponse: function(req) {
    var decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString();
    return decoded;
  },

  extractToken: function(samlpResponse) {
    var doc = new xmldom.DOMParser().parseFromString(samlpResponse);
    var token = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')[0];
    var tokenString = new xmldom.XMLSerializer().serializeToString(token);
  
    return tokenString;
  }
};

function generateUniqueID() {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
}

function generateInstant() {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}