var xtend = require('xtend');
var qs = require('querystring');
var xpath = require('xpath');

var utils = require('./utils');
var AuthenticationFailedError = require('./errors/AuthenticationFailedError');

var WsFederation = module.exports = function WsFederation (realm, homerealm, identityProviderUrl, wreply) {
  this.realm = realm;
  this.homerealm = homerealm;
  this.identityProviderUrl = identityProviderUrl;
  this.wreply = wreply;
};

WsFederation.prototype = {
  getRequestSecurityTokenUrl: function (options) {
    var query = xtend(options || {}, {
      wtrealm: this.realm,
      wa:      'wsignin1.0'
    });

    if (this.homerealm !== '') {
      query.whr = this.homerealm;
    }

    if (this.wreply) {
      query.wreply = this.wreply;
    }

    return this.identityProviderUrl + '?' + qs.encode(query);
  },

  extractToken: function(req) {
    var doc = utils.parseWsFedResponse(req.body['wresult']);

    // //Probe WS-Trust 1.2 namespace (http://schemas.xmlsoap.org/ws/2005/02/trust)
    var token = doc.getElementsByTagNameNS('http://schemas.xmlsoap.org/ws/2005/02/trust', 'RequestedSecurityToken')[0];

    // //Probe WS-Trust 1.3 namespace (http://docs.oasis-open.org/ws-sx/ws-trust/200512)
    if(!token){
      token = doc.getElementsByTagNameNS('http://docs.oasis-open.org/ws-sx/ws-trust/200512', 'RequestedSecurityToken')[0];
    }

    return token && token.firstChild;
  },

  retrieveToken: function(req, callback) {
    if (req.body.wresult.indexOf('<') === -1) {
      return callback(new Error('wresult should be a valid xml'));
    }

    var fault = this.extractFault(req);
    if (fault) {
      return callback(new AuthenticationFailedError(fault.message, fault.detail));
    }

    var token = this.extractToken(req);
    if (!token) {
      return callback(new Error('missing RequestedSecurityToken element'));
    }

    callback(null, token);
  },

  extractFault: function(req) {
    var fault = {};
    var doc = utils.parseWsFedResponse(req.body['wresult']);

    var isFault = xpath.select("//*[local-name(.)='Fault']", doc)[0];
    if (!isFault) {
      return null;
    }

    var codeXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Code']/*[local-name(.)='Value']", doc)[0];
    if (codeXml) {
      fault.code = codeXml.textContent;
    }

    var subCodeXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Code']/*[local-name(.)='Subcode']/*[local-name(.)='Value']", doc)[0];
    if (subCodeXml) {
      fault.subCode = subCodeXml.textContent;
    }

    var messageXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Reason']/*[local-name(.)='Text']", doc)[0];
    if (messageXml) {
      fault.message = messageXml.textContent;
    }

    var detailXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Detail']", doc)[0];
    if (detailXml) {
      fault.detail = detailXml.textContent;
    }

    return fault;
  }
};

Object.defineProperty(WsFederation, 'realm', {
  get: function () {
    return this.realm;
  }
});

Object.defineProperty(WsFederation, 'homeRealm', {
  get: function () {
    return this.homeRealm;
  }
});

Object.defineProperty(WsFederation, 'identityProviderUrl', {
  get: function () {
    return this.identityProviderUrl;
  }
});
