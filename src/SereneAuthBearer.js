
import jwt from 'jsonwebtoken';
import Promise from 'any-promise';
import {ForbiddenError, MethodNotAllowedError, NotAuthenticatedError} from 'http-status-errors';
import debug from 'debug';

const traceRequest = debug('serene-auth-bearer:request');


export default class SereneAuthBearer {
  constructor(secret, options) {
    this.secret = secret;
    this.options = options;
  }


  handle(request, response) {
    traceRequest(`handling ${request.operation.name}:${request.resourceName}`);

    if (!request.resource)
      throw new Error('request.resource not present - use SereneResources before this middleware');

    let acl = request.resource.acl[request.operation.name];

    if (acl) {
      traceRequest('found ACL');

      if (request.user) {
        traceRequest('checking ACL against request user');

        if (!checkAcl(acl, request.user.roles || request.user.scopes || request.user.role || request.user.scope)) {
          throw new ForbiddenError('You do not have sufficient priveleges to complete the requested operation');
        }

      } else {
        traceRequest('checking headers for authentication');

        let header = request.headers && request.headers.authorization || '';
        let [scheme, token] = header.split(' ');

        if (scheme.toLowerCase() === 'bearer') {
          traceRequest('bearer header found');

          return new Promise((resolve, reject) => {
            jwt.verify(token, this.secret, this.options, function (err, token) {
              if (err) {
                traceRequest(`JWT decode error: ${err.name}`);
                reject(new ForbiddenError('Operation forbidden', {cause: err}));

              } else {
                traceRequest('decoded JWT, checking ACL');
                let roles = token.roles || token.scopes || token.role || token.scope;

                if (checkAcl(acl, roles)) {
                  traceRequest('authentication good');
                  resolve();
                } else {
                  traceRequest('forbidden');
                  reject(new ForbiddenError('You do not have sufficient priveleges to complete the requested operation'))
                }
              }
            });
          });

        } else {
          traceRequest('not authenticated, checking ACL for null user');

          if (!checkAcl(acl, null)) {
            traceRequest('should be authenticated');
            throw new NotAuthenticatedError('You need to be authenticated to complete the requested operation');
          } else {
            traceRequest('unauthenticated requests allowed');
          }
        }
      }

    } else {
      traceRequest('method not allowed');
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
