import path from 'path';

import { setup } from '../../../../src/lib/logger';
import loadPlugin from '../../../../src/lib/plugin-loader';

setup([]);

describe('plugin loader', () => {
  const relativePath = path.join(__dirname, './partials/test-plugin-storage');
  const buildConf = (name) => {
    return {
      self_path: path.join(__dirname, './'),
      max_users: 0,
      auth: {
        [`${relativePath}/${name}`]: {},
      },
    };
  };

  describe('auth plugins', () => {
    test('testing auth valid plugin loader', () => {
      const _config = buildConf('verdaccio-plugin');
      // @ts-ignore
      const plugins = loadPlugin(_config, _config.auth, {}, function (plugin) {
        return plugin.authenticate || plugin.allow_access || plugin.allow_publish;
      });

      expect(plugins).toHaveLength(1);
    });

    test('fails on load scoped auth missing package', () => {
      const _config = buildConf('@scope/package');
      try {
        // @ts-ignore
        loadPlugin(_config, { '@scope/package': {} }, {}, undefined);
      } catch (e) {
        expect(e.message).toMatch(
          `@scope/package plugin not found. try \"npm install @scope/package\"`
        );
      }
    });

    // This package is locally installed, just a dummy scoped auth plugin
    // TODO: move this package to the public registry
    test('should load @verdaccio-scope/verdaccio-auth-foo scoped package', () => {
      const _config = buildConf('@verdaccio-scope/verdaccio-auth-foo');
      // @ts-ignore
      const plugins = loadPlugin(
        _config,
        { '@verdaccio-scope/verdaccio-auth-foo': {} },
        {},
        function (plugin) {
          return plugin.authenticate || plugin.allow_access || plugin.allow_publish;
        }
      );
      expect(plugins).toHaveLength(1);
    });

    test('testing storage valid plugin loader', () => {
      const _config = buildConf('verdaccio-es6-plugin');
      // @ts-ignore
      const plugins = loadPlugin(_config, _config.auth, {}, function (p) {
        return p.getPackageStorage;
      });

      expect(plugins).toHaveLength(1);
    });

    test('testing auth plugin invalid plugin', () => {
      const _config = buildConf('invalid-plugin');
      try {
        // @ts-ignore
        loadPlugin(_config, _config.auth, {}, function (p) {
          return p.authenticate || p.allow_access || p.allow_publish;
        });
      } catch (e) {
        expect(e.message).toEqual(
          `"${relativePath}/invalid-plugin" plugin does not have the right code structure`
        );
      }
    });

    test('testing auth plugin invalid plugin sanityCheck', () => {
      const _config = buildConf('invalid-plugin-sanity');
      try {
        // @ts-ignore
        loadPlugin(_config, _config.auth, {}, function (plugin) {
          return plugin.authenticate || plugin.allow_access || plugin.allow_publish;
        });
      } catch (err) {
        expect(err.message).toEqual(
          `sanity check has failed, "${relativePath}/invalid-plugin-sanity" is not a valid plugin`
        );
      }
    });

    test('testing auth plugin no plugins', () => {
      const _config = buildConf('invalid-package');
      try {
        // @ts-ignore
        loadPlugin(_config, _config.auth, {}, function (plugin) {
          return plugin.authenticate || plugin.allow_access || plugin.allow_publish;
        });
      } catch (e) {
        expect(e.message).toMatch('plugin not found');
        expect(e.message).toMatch('/partials/test-plugin-storage/invalid-package');
      }
    });

    test.todo('test middleware plugins');
    test.todo('test storage plugins');
  });
});
