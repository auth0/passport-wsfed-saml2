var passport = require('passport');
var util = require('util');
var saml = require('./saml');
var wsfed = require('./wsfederation');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) {
    throw new Error('Windows Azure Access Control Service authentication strategy requires a verify function');
  }

  this.name = 'wsfed-saml2';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(options);
  this._wsfed =  new wsfed(options.realm, options.homeRealm, options.identityProviderUrl, options.wreply);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  var self = this;
  if (req.body && req.method == 'POST') {
    // We have a response, get the user identity out of it
    var token = this._wsfed.extractToken(req);
    self._saml.validateResponse(token, function (err, profile) {
      if (err) {
        return self.error(err);
      }

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      self._verify(profile, verified);
    });
  } else {
    // Initiate new ws-fed authentication request

    var idpUrl = this._wsfed.getRequestSecurityTokenUrl();
    self.redirect(idpUrl);
  }
};

module.exports = Strategy;