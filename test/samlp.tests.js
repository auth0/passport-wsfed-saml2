var expect = require('chai').expect;
var server = require('./fixture/samlp-server');
var request = require('request');
var qs = require('querystring');
var cheerio = require('cheerio');
var xmldom = require('xmldom');

describe('samlp', function () {
  before(function (done) {
    server.start(done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('samlp flow with assertion signed', function () {
    var r, bod;
    
    before(function (done) {
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
                  'http://localhost:5051/callback', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'])
          .to.equal(server.fakeUser.id);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'])
          .to.equal(server.fakeUser.emails[0].value);
    });
  });

  describe('samlp flow with assertion signed with different cert', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('samlp flow with response signed', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'])
          .to.equal(server.fakeUser.id);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'])
          .to.equal(server.fakeUser.emails[0].value);
    });

  });

  describe('samlp flow with response signed with different cert', function () {
    var r, bod;
    
    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('missing SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5051/callback'
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
      expect(r.headers.location.split('?')[0])
            .to.equal('http://localhost:5051/samlp');
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      expect(querystring).to.have.property('RelayState');
    });
  });

  describe('invalid SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5051/callback',
        form: { SAMLResponse: 'foo' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('samlp request', function () {
    var r, bod;
    
    before(function (done) {
      request.get({
        jar: request.jar(), 
        followRedirect: false,
        uri: 'http://localhost:5051/login'
      }, function (err, resp, b){
        if(err) return callback(err);
        r = resp;
        bod = b;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });

    it('should have SAMLRequest querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
    });

    it('should have RelayState querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('RelayState');
      expect(querystring.RelayState).to.equal(server.relayState);
    });

  });
});

function doSamlpFlow(samlRequestUrl, callbackEndpoint, callback) {
  request.get({
    jar: request.jar(), 
    uri: samlRequestUrl
  }, function (err, response, b){
    if(err) return callback(err);
    expect(response.statusCode)
      .to.equal(200);

    var $ = cheerio.load(b);
    var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
    var RelayState = $('input[name="RelayState"]').attr('value');
    

    request.post({
      jar: request.jar(), 
      uri: callbackEndpoint,
      form: { SAMLResponse: SAMLResponse, RelayState: RelayState }
    }, function(err, response, body) {
      if(err) return callback(err);
      callback(null, { response: response, body: body });
    });
  });
}