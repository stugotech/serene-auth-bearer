
# serene-auth-bearer

Serene middleware to perform Bearer auth with ACLs.

## Installation

    $ npm install --save serene-auth-bearer

## Usage

```js
import Serene from 'serene';
import SereneAuthBearer from 'serene-auth-bearer'
import SereneResources from 'serene-resources';

let service = new Serene();

let resources = {
  widgets: {
    acl: {
      list: '**',
      get: '*',
      create: ['admin', 'support'],
      update: 'admin',
      delete: []
    }
  },
  sprockets: {
    // etc
  }
};

// this package depends on SereneResources, which must be registered first
service.use(new SereneResources(resources));

service.use(new SereneAuthBearer('secret'));

service.use(function (request, response) {
  // this only runs if authentication checked out
});
```

## Documentation

The middleware checks the `Authorization` header for a `Bearer` token, which it decodes as a JSON Web Token (JWT) using the [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) package.

It expects to see a field in the token called one of `roles`, `scopes`, `role` or `scope`, which is either a string or an array of strings stating the role(s)/scope(s) granted to the user.

If the token is invalid (e.g., expired, malformed, etc) or does not grant the necessary scopes, `HTTP 403` is returned.  If there is no `Authorization` header present or it is not of the correct scheme, then `HTTP 401` is returned.

This package depends on the [serene-resources](https://www.npmjs.com/package/serene-resources) package to provide resource descriptions, and looks for the ACL in the `acl` field of said description.  The ACL is given as a hash, with a field for each supported operation.  The following values are supported:

  * `'**'` - allow all requests
  * `'*'` - allow all authenticated requests
  * `[]` - deny all requests
  * `undefined`, `null`, or key not present - `HTTP 405 Method not allowed`
  * any role - the token must have the specified role
  * an array of roles - the token must have any of the specified roles

Therefore, in the [Usage example](#usage) above, the `widgets` resource defines the following constraints:

  * `list` - accessible by anyone
  * `get` - accessible by anyone with a valid token
  * `create` - accessible only by tokens with an `admin` or `support` role
  * `update` - accessible only by tokens with an `admin` role
  * `replace` - not supported
  * `delete` - forbidden to everyone

Note that forbidden to everyone and not supported have the same effect, that all requests are denied: it just depends what message you want to send the requester.


### `constructor(secret, jwtOptions)`

**Params**
  * `secret` - string or buffer containing either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA

  * `options` - options hash passed stright into [`jwt.verify`](https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback)
