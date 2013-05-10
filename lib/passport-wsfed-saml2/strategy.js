var passport = require('passport');
var util = require('util');
var saml = require('./saml');
var wsfed = require('./wsfederation');
var samlp = require('./samlp');

function Strategy (options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  this.options = options || {};

  if (!verify) {
    throw new Error('Windows Azure Access Control Service authentication strategy requires a verify function');
  }

  this.name = 'wsfed-saml2';

  passport.Strategy.call(this);

  this._verify = verify;
  this._saml = new saml.SAML(this.options);
  this._wsfed =  new wsfed(options.realm, options.homeRealm, options.identityProviderUrl, options.wreply);
  this._samlp =  new samlp(this.options);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, opts) {
  var self = this;
  var protocol = opts.protocol || 'wsfed';

  function executeWsfed(req, options) {
    if (req.body && req.method == 'POST' && req.body.wresult) {
      if (req.body.wresult.indexOf('<') === -1) {
        return self.fail('wresult should be a valid xml', 400);
      }

      // We have a response, get the user identity out of it
      var token = self._wsfed.extractToken(req);
      self._saml.validateSamlAssertion(token, function (err, profile) {
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
      var params = self.authorizationParams(opts);
      var idpUrl = self._wsfed.getRequestSecurityTokenUrl(params);
      self.redirect(idpUrl);
    }
  }

  function executeSamlp(req, options) {
    if (req.body && req.method == 'POST' && req.body.SAMLResponse) {
      var samlResponse = self._samlp.decodeResponse(req);
      if (samlResponse.indexOf('<') === -1) {
        return self.fail('SAMLResponse should be a valid xml', 400);
      }

      // We have a response, get the user identity out of it      
      self._saml.validateSamlResponse(samlResponse, function (err) {
        if (err) return self.fail(err, 400);

        var token = self._samlp.extractToken(samlResponse);
        self._saml.validateSamlAssertion(token, function (err, profile) {
          if (err) return self.fail(err, 400);

          var verified = function (err, user, info) {
            if (err) return self.error(err);

            if (!user) return self.fail(info);

            self.success(user, info);
          };

          self._verify(profile, verified);
        });
      });
    } else {
      // Initiate new samlp authentication request
      self._samlp.getSamlRequestUrl(opts, function(err, url) {
        if (err) return self.error(err);

        self.redirect(url);
      });
    }
  }

  switch (protocol) {
    case 'wsfed':
      executeWsfed(req, this.options);
      break;
    case 'samlp': 
      executeSamlp(req, this.options);
      break;
    default:
      throw new Error('not supported protocol: ' + protocol);
  }

  
};

Strategy.prototype.authorizationParams = function(options) {
  return {};
};


module.exports = Strategy;