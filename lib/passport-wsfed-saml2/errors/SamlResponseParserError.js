function SamlResponseParseError (message, detail, status) {
  var err = Error.call(this, message);
  err.name = 'SamlResponseParseError';
  err.message = message || 'Error parsing SAMLResponse';
  err.detail = detail;
  err.status = status || 400;
  return err;
}

SamlResponseParseError.prototype = Object.create(Error.prototype);
SamlResponseParseError.prototype.constructor = SamlResponseParseError;

module.exports = SamlResponseParseError;
