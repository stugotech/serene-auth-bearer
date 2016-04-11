
import jwt from 'jsonwebtoken';
import Serene from 'serene';
import SereneAuthBearer from '../src/SereneAuthBearer';
import SereneResources from 'serene-resources';
import {expect} from 'chai';


describe('SereneAuthBearer', function () {
  let service, resources;

  beforeEach(function () {
    service = new Serene();

    resources = {
      widgets: {
        acl: {
          list: ['*'],
          get: ['foo', 'bar'],
          create: ['**'],
          update: [],
          replace: 'foo'
        }
      }
    };

    service.use(new SereneResources(resources));
    service.use(new SereneAuthBearer('secret'));
  });


  describe('*', function () {
    it('should allow logged in user with no roles', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: []}, 'secret');
      return service.dispatch('list', 'widgets', null, null, null, {authorization});
    });

    it('should allow logged in user with roles', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['a', 'b']}, 'secret');
      return service.dispatch('list', 'widgets', null, null, null, {authorization});
    });

    it('should not allow unauthenticated user', function () {
      return service.dispatch('list', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(401); }
        );
    });
  });


  describe('* (request.user)', function () {
    beforeEach(function () {
      service.handlers = service.handlers.slice(0, 1);
    });

    it('should allow logged in user with no roles', function () {
      service.use((request) => request.user = {roles: []});
      service.use(new SereneAuthBearer());
      return service.dispatch('list', 'widgets');
    });

    it('should allow logged in user with roles', function () {
      service.use((request) => request.user = {roles: ['a', 'b']});
      service.use(new SereneAuthBearer());
      return service.dispatch('list', 'widgets');
    });

    it('should not allow unauthenticated user', function () {
      service.use(new SereneAuthBearer());
      return service.dispatch('list', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(401); }
        );
    });
  });


  describe('stated roles', function () {
    it('should allow user with correct role', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['foo']}, 'secret');
      return service.dispatch('get', 'widgets', null, null, null, {authorization});
    });

    it('should not allow user without correct role', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['fish']}, 'secret');

      return service.dispatch('get', 'widgets',  null, null, null, {authorization})
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(403); }
        );
    });

    it('should not allow unauthenticated user', function () {
      return service.dispatch('get', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(401); }
        );
    });

    it('should work with scopes', function () {
      let authorization = 'Bearer ' + jwt.sign({scopes: ['foo']}, 'secret');
      return service.dispatch('get', 'widgets', null, null, null, {authorization});
    });

    it('should work with role', function () {
      let authorization = 'Bearer ' + jwt.sign({role: 'foo'}, 'secret');
      return service.dispatch('get', 'widgets', null, null, null, {authorization});
    });

    it('should work with scope', function () {
      let authorization = 'Bearer ' + jwt.sign({scope: 'foo'}, 'secret');
      return service.dispatch('get', 'widgets', null, null, null, {authorization});
    });
  });


  describe('**', function () {
    it('should allow logged in user with no roles', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: []}, 'secret');
      return service.dispatch('create', 'widgets', null, null, null, {authorization});
    });

    it('should allow logged in user with roles', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['a', 'b']}, 'secret');
      return service.dispatch('create', 'widgets', null, null, null, {authorization});
    });

    it('should allow unauthenticated user', function () {
      return service.dispatch('create', 'widgets');
    });
  });

  describe('[]', function () {
    it('should not allow unauthenticated user', function () {
      return service.dispatch('update', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(401); }
        );
    });

    it('should not allow authenticated user', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: []}, 'secret');
      return service.dispatch('update', 'widgets', null, null, null, {authorization})
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(403); }
        );
    });
  });


  describe('stated role', function () {
    it('should allow user with correct role', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['foo']}, 'secret');
      return service.dispatch('replace', 'widgets', null, null, null, {authorization});
    });

    it('should not allow user without correct role', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: ['fish']}, 'secret');

      return service.dispatch('replace', 'widgets',  null, null, null, {authorization})
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(403); }
        );
    });

    it('should not allow unauthenticated user', function () {
      return service.dispatch('replace', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(401); }
        );
    });
  });


  describe('undefined', function () {
    it('should 405 for unauthenticated user', function () {
      return service.dispatch('delete', 'widgets')
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(405); }
        );
    });

    it('should 405 for authenticated user', function () {
      let authorization = 'Bearer ' + jwt.sign({roles: []}, 'secret');
      return service.dispatch('delete', 'widgets', null, null, null, {authorization})
        .then(
          () => { throw new Error('expected error'); },
          (err) => { expect(err.status).to.equal(405); }
        );
    });
  });
});
