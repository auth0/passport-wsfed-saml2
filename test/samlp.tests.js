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

  describe('signed samlp response and assertion', function () {
    var user, r, bod, $;

    // SAMLResponse comes from open.feide https://openidp.feide.no
    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5051/callback/samlp-signedresponse-signedassertion',
        form: { SAMLResponse: 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfZjEzOGQyZTUzMWQ0NjI0ZmNhZmQ4OGJlYWNmN2VjMzkwMzRmMmEzNzRkIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxMy0wNy0wN1QxMTo1NToxOFoiIERlc3RpbmF0aW9uPSJodHRwczovL2xvZ2luLWRldjMuYXV0aDAuY29tOjMwMDAvbG9naW4vY2FsbGJhY2siIEluUmVzcG9uc2VUbz0iX2ZkMDY3N2ExZmRmMTU0Y2JmZGQwIj48c2FtbDpJc3N1ZXI+aHR0cHM6Ly9vcGVuaWRwLmZlaWRlLm5vPC9zYW1sOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj4KICA8ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPgogICAgPGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPgogIDxkczpSZWZlcmVuY2UgVVJJPSIjX2YxMzhkMmU1MzFkNDYyNGZjYWZkODhiZWFjZjdlYzM5MDM0ZjJhMzc0ZCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+VXJHUURDSGF0eTRjNzZqTW5oWmZZb09qQ1RFPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5uSGZLUDRzbXliTHQxRTdwNVZJMkttUnZtL3RYMEpVRVNGYUN6ejM4M1RDMWpTU2JaODZKSVJYSVdMRXl1WTJCOTJBNHdmdC8zaHhqV2ZBNTNWUFdsYS93UzBEcitRbzUxU2svTzZNek1tbXRXakx2WVZhTDhvQ3lZUFZHSDlyWXZ4cnlnVXFyVkZDZVZhS3U5Y1VwVWpPdXZTYzM1dUovOEJFZUZ1cTdBMm89PC9kczpTaWduYXR1cmVWYWx1ZT4KPGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQ2l6Q0NBZlFDQ1FDWTh0S2FNYzBCTWpBTkJna3Foa2lHOXcwQkFRVUZBRENCaVRFTE1Ba0dBMVVFQmhNQ1RrOHhFakFRQmdOVkJBZ1RDVlJ5YjI1a2FHVnBiVEVRTUE0R0ExVUVDaE1IVlU1SlRrVlVWREVPTUF3R0ExVUVDeE1GUm1WcFpHVXhHVEFYQmdOVkJBTVRFRzl3Wlc1cFpIQXVabVZwWkdVdWJtOHhLVEFuQmdrcWhraUc5dzBCQ1FFV0dtRnVaSEpsWVhNdWMyOXNZbVZ5WjBCMWJtbHVaWFIwTG01dk1CNFhEVEE0TURVd09EQTVNakkwT0ZvWERUTTFNRGt5TXpBNU1qSTBPRm93Z1lreEN6QUpCZ05WQkFZVEFrNVBNUkl3RUFZRFZRUUlFd2xVY205dVpHaGxhVzB4RURBT0JnTlZCQW9UQjFWT1NVNUZWRlF4RGpBTUJnTlZCQXNUQlVabGFXUmxNUmt3RndZRFZRUURFeEJ2Y0dWdWFXUndMbVpsYVdSbExtNXZNU2t3SndZSktvWklodmNOQVFrQkZocGhibVJ5WldGekxuTnZiR0psY21kQWRXNXBibVYwZEM1dWJ6Q0JuekFOQmdrcWhraUc5dzBCQVFFRkFBT0JqUUF3Z1lrQ2dZRUF0OGpMb3FJMVZUbHhBWjJheGlESVRoV2NBT1hkdThLa1ZVV2FOL1Nvb085TzBRUTdLUlVqU0dLTjlKSzY1QUZSRFhRa1dQQXU0SGxuTzRub1lsRlNMbll5RHhJNjZMQ3I3MXg0bGdGSmpxTGVBdkIvR3FCcUZmSVozWUsvTnJoblVxRndadTYzbkxyWmpjVVp4TmFQak9PU1JTRGFYcHYxa2I1azNqT2lTR0VDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUVVGQUFPQmdRQlFZajRjQWFmV2FZZmpCVTJ6aTFFbHdTdElhSjVueXAvcy84QjhTQVBLMlQ3OU1jTXljY1Azd1NXMTNMSGttTTFqd0tlM0FDRlhCdnFHUU4wSWJjSDQ5aHUwRktoWUZNL0dQREpjSUhGQnNpeU1CWENocHllOXZCYVRORUJDdFUzS2pqeUcwaFJUMm1BUTloK2JrUG1PdmxFby9hSDB4UjY4WjlodzRQRjEzdz09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1scDpTdGF0dXM+PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgSUQ9Il9lYzM1MzRjN2Y2NjYzMjdlNmFmMTU0MzdiZTdiODk5OTU4ZDMwZGY5NzUiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDEzLTA3LTA3VDExOjU1OjE4WiI+PHNhbWw6SXNzdWVyPmh0dHBzOi8vb3BlbmlkcC5mZWlkZS5ubzwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAgPGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICA8ZHM6UmVmZXJlbmNlIFVSST0iI19lYzM1MzRjN2Y2NjYzMjdlNmFmMTU0MzdiZTdiODk5OTU4ZDMwZGY5NzUiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPlZPWVNVQlZZSUNvTWJwbk5INEVCRHhBUWtKTT08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+RW1rR1docVZvZ25vNWhja01UcG9ySHFwT0szVDZpZ2JRVXA2Zmkxc1pvcXFsd3cxSUtmc3REMW1LdzVjM21JcldyNjFnOTh4TFMxLzBnMW5hUWlpT0MzbDl6Y0g3QUFIOVdGWW5JejdGeUE4dmllKzBxTE1Dbno4cVVpZ21HWDNRbEdiQ1QzUHVUNDEzUWlZSm9DT2VXME5zYUpaWUNINUFOWnprSUJsdG9nPTwvZHM6U2lnbmF0dXJlVmFsdWU+CjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUNpekNDQWZRQ0NRQ1k4dEthTWMwQk1qQU5CZ2txaGtpRzl3MEJBUVVGQURDQmlURUxNQWtHQTFVRUJoTUNUazh4RWpBUUJnTlZCQWdUQ1ZSeWIyNWthR1ZwYlRFUU1BNEdBMVVFQ2hNSFZVNUpUa1ZVVkRFT01Bd0dBMVVFQ3hNRlJtVnBaR1V4R1RBWEJnTlZCQU1URUc5d1pXNXBaSEF1Wm1WcFpHVXVibTh4S1RBbkJna3Foa2lHOXcwQkNRRVdHbUZ1WkhKbFlYTXVjMjlzWW1WeVowQjFibWx1WlhSMExtNXZNQjRYRFRBNE1EVXdPREE1TWpJME9Gb1hEVE0xTURreU16QTVNakkwT0Zvd2dZa3hDekFKQmdOVkJBWVRBazVQTVJJd0VBWURWUVFJRXdsVWNtOXVaR2hsYVcweEVEQU9CZ05WQkFvVEIxVk9TVTVGVkZReERqQU1CZ05WQkFzVEJVWmxhV1JsTVJrd0Z3WURWUVFERXhCdmNHVnVhV1J3TG1abGFXUmxMbTV2TVNrd0p3WUpLb1pJaHZjTkFRa0JGaHBoYm1SeVpXRnpMbk52YkdKbGNtZEFkVzVwYm1WMGRDNXViekNCbnpBTkJna3Foa2lHOXcwQkFRRUZBQU9CalFBd2dZa0NnWUVBdDhqTG9xSTFWVGx4QVoyYXhpRElUaFdjQU9YZHU4S2tWVVdhTi9Tb29POU8wUVE3S1JValNHS045Sks2NUFGUkRYUWtXUEF1NEhsbk80bm9ZbEZTTG5ZeUR4STY2TENyNzF4NGxnRkpqcUxlQXZCL0dxQnFGZklaM1lLL05yaG5VcUZ3WnU2M25MclpqY1VaeE5hUGpPT1NSU0RhWHB2MWtiNWszak9pU0dFQ0F3RUFBVEFOQmdrcWhraUc5dzBCQVFVRkFBT0JnUUJRWWo0Y0FhZldhWWZqQlUyemkxRWx3U3RJYUo1bnlwL3MvOEI4U0FQSzJUNzlNY015Y2NQM3dTVzEzTEhrbU0xandLZTNBQ0ZYQnZxR1FOMEliY0g0OWh1MEZLaFlGTS9HUERKY0lIRkJzaXlNQlhDaHB5ZTl2QmFUTkVCQ3RVM0tqanlHMGhSVDJtQVE5aCtia1BtT3ZsRW8vYUgweFI2OFo5aHc0UEYxM3c9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIFNQTmFtZVF1YWxpZmllcj0idXJuOmF1dGgwOmxvZ2luLWRldjMiIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6dHJhbnNpZW50Ij5fOTVkYThhZjQ4MjY4NmEwY2VjZDY0Y2I3Y2FmOGU4NzFiN2FjMTFkYWUxPC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDEzLTA3LTA3VDEyOjAwOjE4WiIgUmVjaXBpZW50PSJodHRwczovL2xvZ2luLWRldjMuYXV0aDAuY29tOjMwMDAvbG9naW4vY2FsbGJhY2siIEluUmVzcG9uc2VUbz0iX2ZkMDY3N2ExZmRmMTU0Y2JmZGQwIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTMtMDctMDdUMTE6NTQ6NDhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTMtMDctMDdUMTI6MDA6MThaIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPnVybjphdXRoMDpsb2dpbi1kZXYzPC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxMy0wNy0wN1QxMToxMTo0MVoiIFNlc3Npb25Ob3RPbk9yQWZ0ZXI9IjIwMTMtMDctMDdUMTk6NTU6MThaIiBTZXNzaW9uSW5kZXg9Il81ZDA2MDZhMGIxZmQ5Nzk4ZDJhMjg3MjE5M2UzOWE5MDdhM2MwYmE0MTUiPjxzYW1sOkF1dGhuQ29udGV4dD48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWw6QXV0aG5Db250ZXh0Pjwvc2FtbDpBdXRoblN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlIE5hbWU9InVpZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPndvbG9za2k8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZ2l2ZW5OYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TWF0aWFzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InNuIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+V29sb3NraTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJjbiIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPk1hdGlhcyBXb2xvc2tpPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9Im1haWwiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYXRpYXN3QGdtYWlsLmNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJlZHVQZXJzb25QcmluY2lwYWxOYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+d29sb3NraUBybmQuZmVpZGUubm88L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZWR1UGVyc29uVGFyZ2V0ZWRJRCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPjFiMTI0NmQ3MjgxOTdiYjQ3ZDA5MzQyYWE0ZjZjM2Y0N2Y0ZTkyYWU8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDowLjkuMjM0Mi4xOTIwMDMwMC4xMDAuMS4xIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+d29sb3NraTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjIuNS40LjQyIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TWF0aWFzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9InVybjpvaWQ6Mi41LjQuNCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1cmkiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciPldvbG9za2k8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDoyLjUuNC4zIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+TWF0aWFzIFdvbG9za2k8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDowLjkuMjM0Mi4xOTIwMDMwMC4xMDAuMS4zIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVyaSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyI+bWF0aWFzd0BnbWFpbC5jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDoxLjMuNi4xLjQuMS41OTIzLjEuMS4xLjYiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj53b2xvc2tpQHJuZC5mZWlkZS5ubzwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMy42LjEuNC4xLjU5MjMuMS4xLjEuMTAiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dXJpIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xYjEyNDZkNzI4MTk3YmI0N2QwOTM0MmFhNGY2YzNmNDdmNGU5MmFlPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should validate response and not signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      /*
      { 
        uid: 'woloski',
        givenName: 'Matias',
        sn: 'Woloski',
        cn: 'Matias Woloski',
        mail: 'matiasw@gmail.com',
        eduPersonPrincipalName: 'woloski@rnd.feide.no',
        eduPersonTargetedID: '1b1246d728197bb47d09342aa4f6c3f47f4e92ae',
        'urn:oid:0.9.2342.19200300.100.1.1': 'woloski',
        'urn:oid:2.5.4.42': 'Matias',
        'urn:oid:2.5.4.4': 'Woloski',
        'urn:oid:2.5.4.3': 'Matias Woloski',
        'urn:oid:0.9.2342.19200300.100.1.3': 'matiasw@gmail.com',
        'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'woloski@rnd.feide.no',
        'urn:oid:1.3.6.1.4.1.5923.1.1.1.10': '1b1246d728197bb47d09342aa4f6c3f47f4e92ae',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': '_95da8af482686a0cecd64cb7caf8e871b7ac11dae1',
        issuer: 'https://openidp.feide.no' 
      }
      */
      expect(user['uid']).to.equal('woloski');
      expect(user['givenName']).to.equal('Matias');
      expect(user['sn']).to.equal('Woloski');
      expect(user['cn']).to.equal('Matias Woloski');
      expect(user['uid']).to.equal('woloski');
      expect(user['urn:oid:0.9.2342.19200300.100.1.1']).to.equal('woloski');
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier']).to.equal('_95da8af482686a0cecd64cb7caf8e871b7ac11dae1');
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