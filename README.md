Passport-wsfed-saml2
=============

This is a ws-federation protocol + SAML2 tokens authentication provider for [Passport](http://passportjs.org/).

The code was originally based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library.

Passport-wsfed-saml2 has been tested to work with both [Windows Azure Active Directory / Access Control Service](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Installation

    $ npm install passport-wsfed-saml2

## Usage

### Configure strategy

This example utilizes a development namespace (auth10-dev) on [Windows Azure Access Control Service](https://www.windowsazure.com/en-us/home/features/identity/) and is using Google as the only identity provider configured for the sample application. 


```javascript
passport.use(new wsfedsaml2(
  {
    path: '/login/callback',
    realm: 'urn:node:app',
    homeRealm: '', // optionally specify an identity provider to avoid showing the idp selector
    identityProviderUrl: 'https://auth10-dev.accesscontrol.windows.net/v2/wsfederation',
    cert: 'MIIDFjCCAf6gAwIBAgIQDRRprj9lv5RBvaQdlFltDzANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTEwOTIxMDMzMjMyWhcNMTIwOTIwMDkzMjMyWjAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCEIAEB/KKT3ehNMy2MQEyJIQ14CnZ8DC2FZgL5Gw3UBSdRb9JinK/gw7yOQtwKfJUqeoZaUSAAdcdbgqwVxOnMBfWiYX7DGlEznSfqYVnjOWjqqjpoe0h6RaOkdWovDtoidmqVV1tWRJFjkj895clPxkLpnqqcycfXtSdZen0SroGyirD2mhMc9ccLbJ3zRnBNjlvpo5zow1zYows09tNC2EhGROL/OS4JNRQnJRICZC+WkA7Igf3xb4btJOzIPYhFiqCGrd/81CHmAyEuNzyc60I5yomDQfZ91Eb5Uk3F7mlfAlYB2aZwDwldLSOlVE8G1E5xFexF/5KyPC4ShNodAgMBAAGjLjAsMAsGA1UdDwQEAwIE8DAdBgNVHQ4EFgQUyYfx/r0czsPgTzitqey+fGMQpkcwDQYJKoZIhvcNAQEFBQADggEBAB5dgQlM3tKS+/cjlvMCPjZH0Iqo/Wxecri3YWi2iVziZ/TQ3dSV+J/iTyduN7rJmFQzTsNERcsgyAwblwnEKXXvlWo8G/+VDIMh3zVPNQFKns5WPkfkhoSVlnZPTQ8zdXAcWgDXbCgvdqIPozdgL+4l0W0XVL1ugA4/hmMXh4TyNd9Qj7MWvlmwVjevpSqN4wG735jAZFHb/L/vvc91uKqP+JvLNj8tPFVxatzi56X1V8jBM61Hx1Z9D0RCDjtmcQVysVEylW9O6mNy6ZrhLm0q5yecWudfBbTKDqRoCHQRjrMU2c5q/ZFDtgjLim7FaNxFbgTyjeRCPclEhfemYVg='
  },
  function(profile, done) {
    findByEmail(profile.email, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
));
```

### Provide the authentication callback

You need to provide a route corresponding to the `path` configuration parameter given to the strategy:

```javascript
app.post('/login/callback',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

