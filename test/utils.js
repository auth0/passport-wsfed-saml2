var expect = require('chai').expect;

var utils = require('../lib/passport-wsfed-saml2/utils');

describe('utils', function () {
  describe('parseSamlAssertion', function () {
    it('should work', function (done) {
      var assertion = utils.parseSamlAssertion('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"></t:RequestSecurityTokenResponse>');
      expect(assertion.childNodes.length)
          .to.equal(1);
      done();
    });

    it('should throw an error with more details', function (done) {
      function parse() {
        try {
          utils.parseSamlAssertion('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><AssertionAssertion></div><div></t:RequestSecurityTokenResponse>');
        } catch (e) {
          return e;
        }
      }

      var err = parse();
      expect(err.name)
          .to.equal('SamlAssertionParserError');
      expect(err.detail.message)
          .to.equal('Opening and ending tag mismatch: "AssertionAssertion" != "div"');
      done();
    });

    it('should throw an error with invalid xml = ""<doc><![CDATA[</doc>""', function (done) {
      expect(() => { utils.parseSamlAssertion('<doc><![CDATA[</doc>'); }).to.throw('SAML Assertion should be a valid xml');
      done();
    });
  });

  describe('parseSamlResponse', function () {
    it('should work', function (done) {
      var response = utils.parseSamlResponse('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"></t:RequestSecurityTokenResponse>');
      expect(response.childNodes.length)
          .to.equal(1);
      done();
    });

    it('should throw an error with more details', function (done) {
      function parse() {
        try {
          utils.parseSamlResponse('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><AssertionAssertion></div><div></t:RequestSecurityTokenResponse>');
        } catch (e) {
          return e;
        }
      }

      var err = parse();
      expect(err.name)
          .to.equal('SamlResponseParserError');
      expect(err.detail.message)
          .to.equal('Opening and ending tag mismatch: "AssertionAssertion" != "div"');
      done();
    });

    it('should throw an error with invalid xml = ""<doc><![CDATA[</doc>""', function (done) {
      expect(() => { utils.parseSamlResponse('<doc><![CDATA[</doc>'); }).to.throw('SAMLResponse should be a valid xml');
      done();
    });
  });

  describe('parseWsFedResponse', function () {
    it('should work', function (done) {
      var response = utils.parseWsFedResponse('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"></t:RequestSecurityTokenResponse>');
      expect(response.childNodes.length)
          .to.equal(1);
      done();
    });

    it('should throw an error with more details', function (done) {
      function parse() {
        try {
          utils.parseWsFedResponse('<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><AssertionAssertion></div><div></t:RequestSecurityTokenResponse>');
        } catch (e) {
          return e;
        }
      }

      var err = parse();
      expect(err.name)
          .to.equal('WSFederationResultParseError');
      expect(err.detail.message)
          .to.equal('Opening and ending tag mismatch: "AssertionAssertion" != "div"');
      done();
    });

    it('should throw an error with invalid xml = ""<doc><![CDATA[</doc>""', function (done) {
      expect(() => { utils.parseWsFedResponse('<doc><![CDATA[</doc>'); }).to.throw('wresult should be a valid xml');
      done();
    });
  });

  describe('parseXmlString', () => {
    it("should parse XML string", () => {
      const xml = "<foo><bar>baz</bar></foo>";
      const result = utils.parseXmlString(xml);
      expect(result.documentElement.nodeName).to.equal("foo");
      expect(result.documentElement.firstChild.nodeName).to.equal("bar");
      expect(result.documentElement.firstChild.firstChild.nodeValue).to.equal(
          "baz"
      );
    });

    it("should throw on = that is not attached to an attribute", () => {
      const xml = "<foo><bar =>baz</bar></foo>";
      expect(() => utils.parseXmlString(xml)).to.throw('Opening and ending tag mismatch: "foo" != "bar"');
    });

    it("should throw on closing elements without opening elements", () => {
      const xml = "<foo></bar></foo>";
      expect(() => utils.parseXmlString(xml)).to.throw('Opening and ending tag mismatch: "foo" != "bar"');
    });

    describe("CDATA sections", () => {
      it("should handle CDATA sections", () => {
        const xml = "<foo><![CDATA[<bar>baz</bar>]]></foo>";
        const result = utils.parseXmlString(xml);
        expect(result.documentElement.nodeName).to.equal("foo");
        expect(result.documentElement.firstChild.nodeValue).to.equal(
            "<bar>baz</bar>"
        );
      });

      it("should not throw CDATA sections on second line", () => {
        const xml = `<foo>
          <![CDATA[<bar>baz</bar>]]>
        </foo>`;
        const result = utils.parseXmlString(xml);
        expect(result.documentElement.nodeName).to.equal("foo");
      });

      it("should not throw multi line CDATA section starting on first line", () => {
        const xml = `<foo><![CDATA[
        
        
        This should all be ignored
        
        ]]>
        </foo>
        `;
        const result = utils.parseXmlString(xml);
        expect(result.documentElement.nodeName).to.equal("foo");
      });

      it("should not throw multi line CDATA section starting on second line", () => {
        const xml = `<foo>
        <![CDATA[
        
        
        This should all be ignored
        
        ]]>
        </foo>
        `;
        const result = utils.parseXmlString(xml);
        expect(result.documentElement.nodeName).to.equal("foo");
      });

      it("should throw if document is single line unclosed CDATA section", () => {
        const xml = `<![CDATA[ this is an unclosed CDATA section`;
        expect(() => utils.parseXmlString(xml)).to.throw('Invalid CDATA starting at position 0');
      });

      it("should throw if document is single line closed CDATA section", () => {
        const xml = `<![CDATA[ this is a closed CDATA section ]]>`;
        expect(() => utils.parseXmlString(xml)).to.throw('CDATA outside of element');
      });

      it("should throw if document is multi line unclosed CDATA section", () => {
        const xml = `<![CDATA[ 
          this is an unclosed CDATA section
        `;
        expect(() => utils.parseXmlString(xml)).to.throw('Invalid CDATA starting at position 0');
      });

      it("should throw with nested CDATA if no start tag", () => {
        const xml = `<![CDATA[ 
          <![CDATA should this be ignored since the other cdata is still open?
            this is a closed CDATA section 
        ]]>`;
        expect(() => utils.parseXmlString(xml)).to.throw('CDATA outside of element');
      });

      it('should not throw if the second CDATA element on a single line is unclosed', () => {
        const xml = `<foo>
          <![CDATA[ignored]]><![CDATA[
          
          just some data
          
          ]]>
        </foo>`;
        expect(() => utils.parseXmlString(xml)).to.not.throw();
      });

      it("should not throw with nested CDATA if with start tag", () => {
        const xml = `<foo><![CDATA[ 
          <![CDATA this CDATA open should be ignored since the other CDATA is still open
            this is a closed CDATA section 
        ]]></foo>`;
        expect(() => utils.parseXmlString(xml)).to.not.throw();
      });

      it("should throw on unclosed CDATA sections on first line", () => {
        const xml = "<foo><![CDATA[<bar>baz</bar>></foo>";
        expect(() => utils.parseXmlString(xml)).to.throw("Invalid CDATA starting at position 5");
      });

      it('should throw on unclosed CDATA sections with closing brackets to finish', () => {
        const xml = '<doc><![CDATA[</doc>]]'
        expect(() => utils.parseXmlString(xml)).to.throw("Invalid CDATA starting at position 5");
      });

      it("should throw on lowercase cdata sections", () => {
        const xml = "<foo><![cdata[flism</foo>";
        expect(() => utils.parseXmlString(xml)).to.throw();
      });

      it("should throw on URL encoded XML", () => {
        const xml = encodeURIComponent("<foo></foo>");
        expect(() => utils.parseXmlString(xml)).to.throw();
      });

      it("should throw on base64 encoded XML", () => {
        const xml = Buffer.from("<foo><![CDATA[flism></foo>", "utf-8").toString(
            "base64"
        );
        expect(() => utils.parseXmlString(xml)).to.throw();
      });

      it("should throw on unclosed CDATA element", () => {
        const xml = "<foo><![CDATA[flism></foo>";
        expect(() => utils.parseXmlString(xml)).to.throw();
      });
    });
  });
});