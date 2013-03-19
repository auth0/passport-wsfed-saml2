var xml2js = require('xml2js');
var xmldom = require('xmldom');

var WsFederation = module.exports = function WsFederation (realm, homerealm, identityProviderUrl, wreply) {
  this.realm = realm;
  this.homerealm = homerealm;
  this.identityProviderUrl = identityProviderUrl;
  this.wreply = wreply;
};

WsFederation.prototype = {
  getRequestSecurityTokenUrl: function () {
    var url;
    if (this.homerealm !== '') {
      url = this.identityProviderUrl + "?wtrealm=" + this.realm + "&wa=wsignin1.0&whr=" + this.homerealm;   
    } else {
      url = this.identityProviderUrl + "?wtrealm=" + this.realm + "&wa=wsignin1.0";
    } 
    if (this.wreply) {
      url += '&wreply=' + encodeURIComponent(this.wreply);
    }
    return url;
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