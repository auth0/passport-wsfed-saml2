function AuthenticationFailedError (message, detail) {
  var err = Error.call(this, message);
  err.name = 'AuthenticationFailedError';
  err.message = message || 'Authentication Failed';
  err.detail = detail;
  return err;
}

AuthenticationFailedError.prototype = Object.create(Error.prototype);
AuthenticationFailedError.prototype.constructor = AuthenticationFailedError;

module.exports = AuthenticationFailedError;