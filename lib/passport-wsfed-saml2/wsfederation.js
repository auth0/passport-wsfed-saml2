const xtend = require('xtend');
const qs = require('querystring');
const xpath = require('xpath');
const xmldom = require('@xmldom/xmldom');

const domParser = new xmldom.DOMParser();

const utils = require('./utils');
const AuthenticationFailedError = require('./errors/AuthenticationFailedError');


const WsFederation = module.exports = function WsFederation (realm, homerealm, identityProviderUrl, wreply) {
  this.realm = realm;
  this.homerealm = homerealm;
  this.identityProviderUrl = identityProviderUrl;
  this.wreply = wreply;
  this.parser = domParser;
};

WsFederation.prototype = {
  getRequestSecurityTokenUrl: function (options) {
    const query = xtend(options || {}, {
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
    const doc = utils.parseWsFedResponse(req.body['wresult'], this.parser);

    // //Probe WS-Trust 1.2 namespace (http://schemas.xmlsoap.org/ws/2005/02/trust)
    let token = doc.getElementsByTagNameNS('http://schemas.xmlsoap.org/ws/2005/02/trust', 'RequestedSecurityToken')[0];

    // //Probe WS-Trust 1.3 namespace (http://docs.oasis-open.org/ws-sx/ws-trust/200512)
    if (!token) {
      token = doc.getElementsByTagNameNS('http://docs.oasis-open.org/ws-sx/ws-trust/200512', 'RequestedSecurityToken')[0];
    }

    return token && token.firstChild;
  },

  retrieveToken: function(req, callback) {
    if (req.body.wresult.indexOf('<') === -1) {
      return callback(new Error('wresult should be a valid xml'));
    }
    const fault = this.extractFault(req);
    if (fault) {
      return callback(new AuthenticationFailedError(fault.message, fault.detail));
    }

    const token = this.extractToken(req);
    if (!token) {
      return callback(new Error('missing RequestedSecurityToken element'));
    }

    // Check for more than one Assertions to conform with spec
    const foundAssertions = xpath.select("//*[local-name(.)='Assertion']", token);
    if (foundAssertions.length > 1) {
      return callback(new Error('A RequestedSecurityToken can contain only one Assertion element.'));
    }

    callback(null, req.body.wresult);
  },

  extractFault: function(req) {
    const fault = {};
    let doc;
    try {
       doc = utils.parseWsFedResponse(req.body['wresult'], this.parser);
    } catch (err) {
      return err;
    }

    const isFault = xpath.select("//*[local-name(.)='Fault']", doc)[0];
    if (!isFault) {
      return null;
    }

    const codeXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Code']/*[local-name(.)='Value']", doc)[0];
    if (codeXml) {
      fault.code = codeXml.textContent;
    }

    const subCodeXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Code']/*[local-name(.)='Subcode']/*[local-name(.)='Value']", doc)[0];
    if (subCodeXml) {
      fault.subCode = subCodeXml.textContent;
    }

    const messageXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Reason']/*[local-name(.)='Text']", doc)[0];
    if (messageXml) {
      fault.message = messageXml.textContent;
    }

    const detailXml = xpath.select("//*[local-name(.)='Fault']/*[local-name(.)='Detail']", doc)[0];
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