function WSFederationResultParseError (message, detail, status) {
  var err = Error.call(this, message);
  err.name = 'WSFederationResultParseError';
  err.message = message || 'Error parsing wresult';
  err.detail = detail;
  err.status = status || 400;
  return err;
}

WSFederationResultParseError.prototype = Object.create(Error.prototype);
WSFederationResultParseError.prototype.constructor = WSFederationResultParseError;

module.exports = WSFederationResultParseError;
