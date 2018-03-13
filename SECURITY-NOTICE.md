Security vulnerability details for passport-wsfed-saml2 < 3.0.10
===============================================================

A vulnerability was found in the validation of a SAML signature. The validation doesn't ensure that the "Signature" tag is at the proper location inside an "Assertion" tag. This leads to a signature relocation attack where the attacker can corrupt one field of data while
maintaining the signature valid. This could allow an authenticated attacker to "remove" one group from his assertion or corrupt another field of an assertion.

Updated packages are available on npm. To ensure delivery of additional bug fixes moving forward, please make sure your `package.json` file is updated to take patch and minor level updates of our libraries. See below:

```
{
  "dependencies": {
    "passport-wsfed-saml2": "^3.0.10"
  }
}
```

## Upgrade Notes

This fix patches the library that your application runs, but will not impact your users, their current state, or any existing sessions.

You can read more details regarding the vulnerability [here](https://auth0.com/docs/security/bulletins/cve-2018-8085).



Security vulnerability details for passport-wsfed-saml2 < 3.0.5
===============================================================

A vulnerability has been discovered in the passport-wsfed-saml2 library affecting versions < 3.0.5. This vulnerability allows an attacker to impersonate another user and potentially elevate their privileges if the SAML identity provider:

* signs SAML response and signs assertion
* does not sign SAML response and signs assertion

Developers using the passport-wsfed-saml2 Passport Strategy need to upgrade to the latest version: 3.0.5.

Updated packages are available on npm. To ensure delivery of additional bug fixes moving forward, please make sure your `package.json` file is updated to take patch and minor level updates of our libraries. See below:

```
{
  "dependencies": {
    "passport-wsfed-saml2": "^3.0.5"
  }
}
```

## Upgrade Notes

This fix patches the library that your application runs, but will not impact your users, their current state, or any existing sessions.
