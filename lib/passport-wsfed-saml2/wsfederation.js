var xmldom = require('xmldom');
var xtend = require('xtend');
var qs = require('querystring');

var WsFederation = module.exports = function WsFederation (realm, homerealm, identityProviderUrl, wreply, identityProviderXmlNamespace) {
  this.realm = realm;
  this.homerealm = homerealm;
  this.identityProviderUrl = identityProviderUrl;
  this.wreply = wreply;
  this.identityProviderXmlNamespace = identityProviderXmlNamespace;

  if(!this.identityProviderXmlNamespace){
    this.identityProviderXmlNamespace = 'http://schemas.xmlsoap.org/ws/2005/02/trust';
  }
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
    var token = doc.getElementsByTagNameNS(this.identityProviderXmlNamespace, 'RequestedSecurityToken')[0];
  
    return token && token.firstChild;
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

Object.defineProperty(WsFederation, 'identityProviderXmlNamespace', {
  get: function () {
    return this.identityProviderXmlNamespace;
  }
});