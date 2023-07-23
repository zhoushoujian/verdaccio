// this file is not aim to be tested, just to check flow definitions
import { Callback } from '@verdaccio/types';
import {
  Config as AppConfig,
  IPluginAuth,
  Logger,
  PackageAccess,
  PluginOptions,
  RemoteUser,
} from '@verdaccio/types';

import Config from '../../../../src/lib/config';
import { logger } from '../../../../src/lib/logger';

class ExampleAuthPlugin implements IPluginAuth<{}> {
  config: AppConfig;
  logger: Logger;

  constructor(config: AppConfig, options: PluginOptions<{}>) {
    this.config = config;
    this.logger = options.logger;
  }

  adduser(user: string, password: string, cb: Callback): void {
    // pragma: allowlist secret
    cb();
  }

  changePassword(username, password, newPassword, cb: Callback): void {
    cb();
  }

  authenticate(user: string, password: string, cb: Callback): void {
    // pragma: allowlist secret
    cb();
  }

  allow_access(user: RemoteUser, pkg: PackageAccess, cb: Callback): void {
    cb();
  }

  allow_publish(user: RemoteUser, pkg: PackageAccess, cb: Callback): void {
    cb();
  }
}

type SubTypePackageAccess = PackageAccess & {
  sub?: boolean;
};

class ExampleAuthCustomPlugin implements IPluginAuth<{}> {
  config: AppConfig;
  logger: Logger;

  constructor(config: AppConfig, options: PluginOptions<{}>) {
    this.config = config;
    this.logger = options.logger;
  }

  adduser(user: string, password: string, cb: Callback): void {
    cb();
  }

  changePassword(username, password, newPassword, cb: Callback): void {
    cb();
  }

  authenticate(user: string, password: string, cb: Callback): void {
    cb();
  }

  allow_access(user: RemoteUser, pkg: SubTypePackageAccess, cb: Callback): void {
    cb();
  }

  allow_publish(user: RemoteUser, pkg: SubTypePackageAccess, cb: Callback): void {
    cb();
  }
}

const config1: AppConfig = new Config({
  storage: './storage',
  self_path: '/home/sotrage',
});

const options: PluginOptions<{}> = {
  config: config1,
  logger: logger.child({ sub: 'out' }),
};

const auth = new ExampleAuthPlugin(config1, options);
const authSub = new ExampleAuthCustomPlugin(config1, options);
const remoteUser: RemoteUser = {
  groups: [],
  real_groups: [],
  name: 'test',
};

auth.authenticate('user', 'pass', () => {});
auth.allow_access(remoteUser, { access: [], publish: [], proxy: [] }, () => {});
auth.allow_publish(remoteUser, { access: [], publish: [], proxy: [] }, () => {});
authSub.authenticate('user', 'pass', () => {});
authSub.allow_access(remoteUser, { access: [], publish: [], proxy: [], sub: true }, () => {});
authSub.allow_publish(remoteUser, { access: [], publish: [], proxy: [], sub: true }, () => {});
