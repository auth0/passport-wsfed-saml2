var xmldom = require('xmldom');
var xtend = require('xtend');
var qs = require('querystring');

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
    //var parser = new xml2js.Parser();

    var doc = new xmldom.DOMParser().parseFromString(req.body['wresult']);
    
    var token = doc.getElementsByTagNameNS('http://schemas.xmlsoap.org/ws/2005/02/trust', 'RequestedSecurityToken')[0].firstChild;
    var tokenString = new xmldom.XMLSerializer().serializeToString(token);
  
    return tokenString;
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