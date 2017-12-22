var chai      = require('chai');
var uri       = require('url');
var expect    = require('chai').expect;
var passport  = require('chai-passport-strategy');
var Strategy  = require('../../lib/passport-wsfed-saml2').Strategy;

chai.use(passport);

describe('samlp - using default session state store', function() {

  var SAMLResponse = 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfOGU4ZGM1ZjY5YTk4Y2M0YzFmZjM0MjdlNWNlMzQ2MDZmZDY3MmY5MWU2IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNC0wNy0xN1QwMTowMTo0OFoiIERlc3RpbmF0aW9uPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyIgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl80ZmVlM2IwNDYzOTVjNGU3NTEwMTFlOTdmODkwMGI1MjczZDU2Njg1Ij4NCiAgPHNhbWw6SXNzdWVyPmh0dHA6Ly9pZHAuZXhhbXBsZS5jb20vbWV0YWRhdGEucGhwPC9zYW1sOklzc3Vlcj4NCiAgPHNhbWxwOlN0YXR1cz4NCiAgICA8c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+DQogIDwvc2FtbHA6U3RhdHVzPg0KICA8c2FtbDpBc3NlcnRpb24geG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiBJRD0iX2Q3MWEzYThlOWZjYzQ1YzllOWQyNDhlZjcwNDkzOTNmYzhmMDRlNWY3NSIgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDctMTdUMDE6MDE6NDhaIj4NCiAgICA8c2FtbDpJc3N1ZXI+aHR0cDovL2lkcC5leGFtcGxlLmNvbS9tZXRhZGF0YS5waHA8L3NhbWw6SXNzdWVyPg0KICAgIDxzYW1sOlN1YmplY3Q+DQogICAgICA8c2FtbDpOYW1lSUQgU1BOYW1lUXVhbGlmaWVyPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvbWV0YWRhdGEucGhwIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCI+X2NlM2QyOTQ4YjRjZjIwMTQ2ZGVlMGEwYjNkZDZmNjliNmNmODZmNjJkNzwvc2FtbDpOYW1lSUQ+DQogICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+DQogICAgICAgIDxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMjAyNC0wMS0xOFQwNjoyMTo0OFoiIFJlY2lwaWVudD0iaHR0cDovL3NwLmV4YW1wbGUuY29tL2RlbW8xL2luZGV4LnBocD9hY3MiIEluUmVzcG9uc2VUbz0iT05FTE9HSU5fNGZlZTNiMDQ2Mzk1YzRlNzUxMDExZTk3Zjg5MDBiNTI3M2Q1NjY4NSIvPg0KICAgICAgPC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+DQogICAgPC9zYW1sOlN1YmplY3Q+DQogICAgPHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTQtMDctMTdUMDE6MDE6MThaIiBOb3RPbk9yQWZ0ZXI9IjIwMjQtMDEtMThUMDY6MjE6NDhaIj4NCiAgICAgIDxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+DQogICAgICAgIDxzYW1sOkF1ZGllbmNlPmh0dHA6Ly9zcC5leGFtcGxlLmNvbS9kZW1vMS9tZXRhZGF0YS5waHA8L3NhbWw6QXVkaWVuY2U+DQogICAgICA8L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj4NCiAgICA8L3NhbWw6Q29uZGl0aW9ucz4NCiAgICA8c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTQtMDctMTdUMDE6MDE6NDhaIiBTZXNzaW9uTm90T25PckFmdGVyPSIyMDI0LTA3LTE3VDA5OjAxOjQ4WiIgU2Vzc2lvbkluZGV4PSJfYmU5OTY3YWJkOTA0ZGRjYWUzYzBlYjQxODlhZGJlM2Y3MWUzMjdjZjkzIj4NCiAgICAgIDxzYW1sOkF1dGhuQ29udGV4dD4NCiAgICAgICAgPHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+DQogICAgICA8L3NhbWw6QXV0aG5Db250ZXh0Pg0KICAgIDwvc2FtbDpBdXRoblN0YXRlbWVudD4NCiAgICA8c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+DQogICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0idWlkIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4NCiAgICAgICAgPHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dGVzdDwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4NCiAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+DQogICAgICA8c2FtbDpBdHRyaWJ1dGUgTmFtZT0ibWFpbCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPnRlc3RAZXhhbXBsZS5jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICA8L3NhbWw6QXR0cmlidXRlPg0KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9ImVkdVBlcnNvbkFmZmlsaWF0aW9uIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj4NCiAgICAgICAgPHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+dXNlcnM8L3NhbWw6QXR0cmlidXRlVmFsdWU+DQogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPmV4YW1wbGVyb2xlMTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4NCiAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+DQogICAgPC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4NCiAgPC9zYW1sOkFzc2VydGlvbj4NCjwvc2FtbHA6UmVzcG9uc2U+';
  
  describe('without session key option', function() {
    
    describe('issuing authorization request', function() {
      var strategy = new Strategy({
        protocol: 'samlp',
        path: '/callback',
        realm: 'https://auth0-dev-ed.my.salesforce.com',
        identityProviderUrl: 'http://www.example.com/samlp',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        state: true
      }, function () {});
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.RelayState).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
          expect(request.session['samlp:www.example.com'].state).to.have.length(24);
          expect(request.session['samlp:www.example.com'].state).to.equal(u.query.RelayState);
        });
      });
      
      describe('that redirects to service provider with other data in session', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
              req.session['samlp:www.example.com'] = {};
              req.session['samlp:www.example.com'].foo = 'bar';
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.RelayState).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['samlp:www.example.com'].state).to.have.length(24);
          expect(request.session['samlp:www.example.com'].state).to.equal(u.query.RelayState);
        });
        
        it('should preserve other data in session', function() {
          expect(request.session['samlp:www.example.com'].foo).to.equal('bar');
        });
      });
      
      describe('that errors due to lack of session support in app', function() {
        var request, err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      });
    });
    
    describe('processing response to authorization request', function() {
      var strategy = new Strategy({
        protocol: 'samlp',
        path: '/callback',
        realm: 'https://auth0-dev-ed.my.salesforce.com',
        identityProviderUrl: 'http://www.example.com/samlp',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        state: true
      },
      function (profile, done) {
        return done(null, profile, { message: 'Hello' });
      });

      strategy._samlp.validateSamlResponse = function(token, done) {
        expect(token).to.be.an.object;
        done(null, { id: '1234' });
      };
      
      describe('that was approved', function() {
        var request, user, info;
  
        before(function (done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['samlp:www.example.com'] = {};
              req.session['samlp:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      
        it('should remove state from session', function() {
          expect(request.session['samlp:www.example.com']).to.be.undefined;
        });
      });
      
      describe('that was approved with other data in the session', function() {
        var request, user, info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['samlp:www.example.com'] = {};
              req.session['samlp:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session['samlp:www.example.com'].foo = 'bar';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      
        it('should preserve other data from session', function() {
          expect(request.session['samlp:www.example.com'].state).to.be.undefined;
          expect(request.session['samlp:www.example.com'].foo).to.equal('bar');
        });
      });
      
      describe('that fails due to state being invalid', function() {
        var request, info, status;
  
        before(function (done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.method = 'POST';
              req.session = {};
              req.session['samlp:www.example.com'] = {};
              req.session['samlp:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Invalid authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      
        it('should remove state from session', function() {
          expect(request.session['samlp:www.example.com']).to.be.undefined;
        });
      });
      
      describe('that fails due to provider-specific state not found in session', function() {
        var request, info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      });
      
      describe('that fails due to provider-specific state lacking state value', function() {
        var request, info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['samlp:www.example.com'] = {};
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      });
      
      describe('that errors due to lack of session support in app', function() {
        var request, err;
  
        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      });
    });
  });
  
  describe('with session key option', function() {
    var strategy = new Strategy({
      protocol: 'samlp',
      path: '/callback',
      realm: 'https://auth0-dev-ed.my.salesforce.com',
      identityProviderUrl: 'http://www.example.com/samlp',
      thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
      state: true,
      sessionKey: 'samlp:example'
    },
    function (profile, done) {
      return done(null, profile, { message: 'Hello' });
    });

    strategy._samlp.validateSamlResponse = function(token, done) {
      expect(token).to.be.an.object;
      done(null, { id: '1234' });
    };
    
    describe('issuing authorization request', function() {
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function (done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.RelayState).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['samlp:example'].state).to.have.length(24);
          expect(request.session['samlp:example'].state).to.equal(u.query.RelayState);
        });
      });
    });
    
    describe('processing response to authorization request', function() {
      
      describe('that was approved', function() {
        var request, user, info;
  
        before(function (done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.SAMLResponse = SAMLResponse;
              req.body.RelayState = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['samlp:example'] = {};
              req.session['samlp:example']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
      
        it('should remove state from session', function() {
          expect(request.session['samlp:example']).to.be.undefined;
        });
      });
    });
  });
});
