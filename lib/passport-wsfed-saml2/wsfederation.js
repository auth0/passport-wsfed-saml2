var xmldom = require('xmldom');
var xtend = require('xtend');
var qs = require('querystring');
var xpath = require('xpath');
const fs = require("fs");
const crypto = require("crypto");
const ursa_purejs = require("ursa-purejs");

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
    var doc = new xmldom.DOMParser().parseFromString(req.body['wresult']);
    //Probe WS-Trust 1.2 namespace (http://schemas.xmlsoap.org/ws/2005/02/trust)
    var token = doc.getElementsByTagNameNS('http://schemas.xmlsoap.org/ws/2005/02/trust', 'RequestedSecurityToken')[0];
    //Probe WS-Trust 1.3 namespace (http://docs.oasis-open.org/ws-sx/ws-trust/200512) 
    if(!token){
      token = doc.getElementsByTagNameNS('http://docs.oasis-open.org/ws-sx/ws-trust/200512', 'RequestedSecurityToken')[0];
    }
    // Is the SAML token encrypted?
    if (!token || token.firstChild.nodeName !== 'xenc:EncryptedData') {
        // no. return it.
        console.log('SAML token not encrypted. return');
        return token && token.firstChild;
    }
    // We need to decrypt the SAML token...
    // Grab the CipherValue elements. There will be two:
    //   0. The encryption key for the SAML token, encrypted by ADFS using the rsa-oaep-mgf1p 
    //      algo and the public key of the encryption certificate configured in the relying party.
    //   1. The SAML token, encrypted using the aes-256-cbc algo with the key from #0 ^^^
    const ciphers = token.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'CipherValue');
    const aesPasswordCipher = ciphers[0].textContent;
    const samlTokenCipher = ciphers[1].textContent;
    // Decrypt the password for the SAML token.
    const certPrivateKey = '../certs/token-signing.key';
    if (!fs.existsSync(certPrivateKey)) {
      throw new Error("The SAML token is encrypted and you haven't provided the necessary private key at the root of you project in certs/token-signing.key. Supported algo: aes-256-cbc");
    }

    const tokenSigningKey = ursa_purejs.createPrivateKey(fs.readFileSync(certPrivateKey));
    const aesPassword = tokenSigningKey.decrypt(aesPasswordCipher, 'base64');
    // Decrypt the SAML token.
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesPassword, crypto.randomBytes(16));
    let saml = decipher.update(new Buffer(samlTokenCipher, 'base64'), 'binary', 'utf8');
    saml += decipher.final('utf8');
    // Parse the XML and return the token.
    return new xmldom.DOMParser().parseFromString(saml).firstChild;
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
    var doc = new xmldom.DOMParser().parseFromString(req.body['wresult']);

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