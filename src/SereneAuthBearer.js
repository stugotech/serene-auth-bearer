
import jwt from 'jsonwebtoken';
import Promise from 'any-promise';
import {NotAuthenticatedError, ForbiddenError} from 'http-status-errors';


export default class SereneAuthBearer {
  constructor(secret, options) {
    this.secret = secret;
    this.options = options;
  }


  handle(request, response) {
    if (!request.resource)
      throw new Error('request.resource not present - use SereneResources before this middleware');

    let header = request.headers && request.headers.authorization || '';
    let [scheme, token] = header.split(' ');

    if (scheme.toLowerCase() === 'bearer') {
      return new Promise((resolve, reject) => {
        jwt.verify(token, this.secret, this.options, function (err, token) {
          if (err) {
            reject(new ForbiddenError('Operation forbidden', {cause: err}));

          } else {
            let roles = token.roles || token.scopes || token.role || token.scope;

            if (checkAcl(request.resource.acl, request.operation.name, roles)) {
              resolve();
            } else {
              reject(new ForbiddenError('You do not have sufficient priveleges to complete the requested operation'))
            }
          }
        });
      });

    } else if (!checkAcl(request.resource.acl, request.operation.name, null)) {
      throw new NotAuthenticatedError('You need to be authenticated to complete the requested operation');
    }
  }
};


function checkAcl(acl, operation, roles) {
  let op = acl[operation];

  if (!op || op.length === 1 && op[0] === '**') {
    return true;

  } else if (op.length === 1 && op[0] === '*' && roles !== null) {
    return true;

  } else if (!op.length) {
    return false;

  } else if (roles !== null) {
    if (!Array.isArray(roles))
      roles = [roles];

    let map = {};

    for (let role of roles) {
      map[role] = true;
    }

    for (let role of op) {
      if (map[role])
        return true;
    }

    return false;

  } else {
    return false;
  }
}
