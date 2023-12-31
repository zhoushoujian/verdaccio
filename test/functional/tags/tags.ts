import _ from 'lodash';

import { HTTP_STATUS } from '../../../src/lib/constants';
import { readFile } from '../lib/test.utils';

const readTags = () => readFile('../fixtures/tags.json');

export default function (server, express) {
  test('tags - testing for 404', () => {
    return (
      server
        .getPackage('testexp_tags')
        // shouldn't exist yet
        .status(HTTP_STATUS.NOT_FOUND)
        .body_error(/no such package/)
    );
  });

  describe('tags', () => {
    beforeAll(function () {
      express.get('/testexp_tags', function (req, res) {
        let f = readTags()
          .toString()
          .replace(/__NAME__/g, 'testexp_tags');
        res.send(JSON.parse(f));
      });
    });

    test('fetching package again', () => {
      return server
        .getPackage('testexp_tags')
        .status(200)
        .then(function (body) {
          expect(_.isObject(body.versions['1.1.0'])).toBe(true);
          // note: 5.4.3 is invalid tag, 0.1.3alpha is highest semver
          expect(body['dist-tags'].latest).toEqual('1.1.0');
          expect(body['dist-tags'].bad).toEqual(undefined);
        });
    });

    const versions = ['0.1.1alpha', '0.1.1-alpha', '0000.00001.001-alpha'];

    versions.forEach(function (ver) {
      test('fetching ' + ver, () => {
        return server
          .request({ uri: '/testexp_tags/' + ver })
          .status(200)
          .then(function (body) {
            expect(body.version).toEqual('0.1.1alpha');
          });
      });
    });
  });

  describe('dist-tags methods', () => {
    beforeAll(function () {
      express.get('/testexp_tags2', function (req, res) {
        let f = readTags()
          .toString()
          .replace(/__NAME__/g, 'testexp_tags2');
        res.send(JSON.parse(f));
      });
    });

    // populate cache
    beforeAll(function () {
      return server.getPackage('testexp_tags2').status(200);
    });

    test('fetching tags', () => {
      return server
        .request({
          method: 'GET',
          uri: '/-/package/testexp_tags2/dist-tags',
        })
        .status(200)
        .then(function (body) {
          const expected = {
            latest: '1.1.0',
          };

          expect(body).toEqual(expected);
        });
    });

    test('merging tags', () => {
      return server
        .request({
          method: 'POST',
          uri: '/-/package/testexp_tags2/dist-tags',
          json: {
            foo: '0.1.2',
            quux: '0.1.0',
          },
        })
        .status(201)
        .body_ok(/updated/)
        .then(function () {
          return server
            .request({
              method: 'GET',
              uri: '/-/package/testexp_tags2/dist-tags',
            })
            .status(200)
            .then(function (body) {
              const expected = {
                latest: '1.1.0',
                foo: '0.1.2',
                quux: '0.1.0',
              };

              expect(body).toEqual(expected);
            });
        });
    });

    test('should add a dist-tag called foo', () => {
      return server
        .request({
          method: 'PUT',
          uri: '/-/package/testexp_tags2/dist-tags/foo',
          json: '0.1.3alpha',
        })
        .status(201)
        .body_ok(/tagged/)
        .then(function () {
          return server
            .request({
              method: 'GET',
              uri: '/-/package/testexp_tags2/dist-tags',
            })
            .status(200)
            .then(function (body) {
              const expected = {
                foo: '0.1.3alpha',
                quux: '0.1.0',
                latest: '1.1.0',
              };

              expect(body).toEqual(expected);
            });
        });
    });

    test('should remove a dis-tag called quux', () => {
      return server
        .request({
          method: 'DELETE',
          uri: '/-/package/testexp_tags2/dist-tags/latest',
        })
        .status(201)
        .body_ok(/removed/)
        .then(function () {
          return server
            .request({
              method: 'GET',
              uri: '/-/package/testexp_tags2/dist-tags',
            })
            .status(200)
            .then(function (body) {
              const expected = {
                latest: '1.1.0',
                quux: '0.1.0',
                foo: '0.1.3alpha',
              };

              expect(body).toEqual(expected);
            });
        });
    });

    test('should remove a dis-tag called foo', () => {
      return server
        .request({
          method: 'DELETE',
          uri: '/-/package/testexp_tags2/dist-tags/foo',
        })
        .status(201)
        .body_ok(/removed/)
        .then(function () {
          return server
            .request({
              method: 'GET',
              uri: '/-/package/testexp_tags2/dist-tags',
            })
            .status(200)
            .then(function (body) {
              const expected = {
                latest: '1.1.0',
                quux: '0.1.0',
              };

              expect(body).toEqual(expected);
            });
        });
    });
  });
}
