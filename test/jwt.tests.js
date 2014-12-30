var expect = require('chai').expect;
var jwt = require('jsonwebtoken');
var fs = require('fs');
var Strategy = require('../lib/passport-wsfed-saml2/strategy');

var cert = {
  pub: fs.readFileSync(__dirname + '/test-auth0.pem'),
  key: fs.readFileSync(__dirname + '/test-auth0.key')
};

var s = new Strategy({
  cert: cert.pub,
  jwt: {
    algorithm: 'RS256'
  }
}, function (profile, done) {
  done(null, profile);
});

describe('jwt support', function () {

  it('should work', function (done) {
    s.success = function (user) {
      expect(user.foo).to.equal('bar');
      done();
    };

    s.fail = done;
    s.error = done;

    var token = jwt.sign({
      foo: 'bar'
    }, cert.key, { algorithm: 'RS256'});

    var req = {
      method: 'POST',
      body: {
        wresult: token
      }
    };

    s.authenticate(req, {});
  });

});