function SamlAssertionParserError (message, detail, status) {
  var err = Error.call(this, message);
  err.name = 'SamlAssertionParserError';
  err.message = message || 'Error parsing SAML Assertion';
  err.detail = detail;
  err.status = status || 400;
  return err;
}

SamlAssertionParserError.prototype = Object.create(Error.prototype);
SamlAssertionParserError.prototype.constructor = SamlAssertionParserError;

module.exports = SamlAssertionParserError;
