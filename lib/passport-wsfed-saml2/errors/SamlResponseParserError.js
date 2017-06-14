function SamlResponseParserError (message, detail, status) {
  var err = Error.call(this, message);
  err.name = 'SamlResponseParserError';
  err.message = message || 'Error parsing SAMLResponse';
  err.detail = detail;
  err.status = status || 400;
  return err;
}

SamlResponseParserError.prototype = Object.create(Error.prototype);
SamlResponseParserError.prototype.constructor = SamlResponseParserError;

module.exports = SamlResponseParserError;
