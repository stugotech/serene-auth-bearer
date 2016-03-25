
import jwt from 'jsonwebtoken';
import Promise from 'any-promise';
import {ForbiddenError, MethodNotAllowedError, NotAuthenticatedError} from 'http-status-errors';


export default class SereneAuthBearer {
  constructor(secret, options) {
    this.secret = secret;
    this.options = options;
  }


  handle(request, response) {
    if (!request.resource)
      throw new Error('request.resource not present - use SereneResources before this middleware');

    let acl = request.resource.acl[request.operation.name];

    if (acl) {
      let header = request.headers && request.headers.authorization || '';
      let [scheme, token] = header.split(' ');

      if (scheme.toLowerCase() === 'bearer') {
        return new Promise((resolve, reject) => {
          jwt.verify(token, this.secret, this.options, function (err, token) {
            if (err) {
              reject(new ForbiddenError('Operation forbidden', {cause: err}));

            } else {
              let roles = token.roles || token.scopes || token.role || token.scope;

              if (checkAcl(acl, roles)) {
                resolve();
              } else {
                reject(new ForbiddenError('You do not have sufficient priveleges to complete the requested operation'))
              }
            }
          });
        });

      } else if (!checkAcl(acl, null)) {
        throw new NotAuthenticatedError('You need to be authenticated to complete the requested operation');
      }

    } else {
      throw new MethodNotAllowedError(`operation ${request.operation.name} not allowed for resource ${request.resourceName}`);
    }
  }
};


function checkAcl(acl, roles) {
  if (!Array.isArray(acl)) {
    acl = [acl];
  }

  if (acl.length === 1 && acl[0] === '**') {
    return true;

  } else if (acl.length === 1 && acl[0] === '*' && roles !== null) {
    return true;

  } else if (!acl.length) {
    return false;

  } else if (roles !== null) {
    if (!Array.isArray(roles))
      roles = [roles];

    let map = {};

    for (let role of roles) {
      map[role] = true;
    }

    for (let role of acl) {
      if (map[role])
        return true;
    }

    return false;

  } else {
    return false;
  }
}
