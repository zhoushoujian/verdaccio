import buildDebug from 'debug';
import fs from 'fs';
import _ from 'lodash';
import mkdirp from 'mkdirp';
import Path from 'path';

import { logger } from './logger';
import { fileExists, folderExists } from './utils';

const debug = buildDebug('verdaccio:config');

const CONFIG_FILE = 'config.yaml';
const XDG = 'xdg';
const WIN = 'win';
const WIN32 = 'win32';
// eslint-disable-next-line
const pkgJSON = require('../../package.json');

export type SetupDirectory = {
  path: string;
  type: string;
};

/**
 * Find and get the first config file that match.
 * @return {String} the config file path
 */
function findConfigFile(configPath?: string): string {
  if (typeof configPath !== 'undefined') {
    return Path.resolve(configPath);
  }

  const configPaths: SetupDirectory[] = getConfigPaths();
  debug('%o posible locations found', configPaths.length);
  if (_.isEmpty(configPaths)) {
    throw new Error('no configuration files can be processed');
  }

  const primaryConf: any = _.find(configPaths, (configLocation: any) =>
    fileExists(configLocation.path)
  );
  if (typeof primaryConf !== 'undefined') {
    debug('previous location exist already %s', primaryConf?.path);
    return primaryConf.path;
  }

  return createConfigFile(_.head(configPaths)).path;
}

function createConfigFile(configLocation: any): SetupDirectory {
  createConfigFolder(configLocation);

  const defaultConfig = updateStorageLinks(configLocation, readDefaultConfig());

  fs.writeFileSync(configLocation.path, defaultConfig);

  return configLocation;
}

function readDefaultConfig(): string {
  return fs.readFileSync(require.resolve('../../conf/default.yaml'), 'utf-8');
}

function createConfigFolder(configLocation): void {
  mkdirp.sync(Path.dirname(configLocation.path));
  logger.info({ file: configLocation.path }, 'Creating default config file in @{file}');
}

function updateStorageLinks(configLocation, defaultConfig): string {
  if (configLocation.type !== XDG) {
    return defaultConfig;
  }

  // $XDG_DATA_HOME defines the base directory relative to which user specific data files should be stored,
  // If $XDG_DATA_HOME is either not set or empty, a default equal to $HOME/.local/share should be used.
  let dataDir =
    process.env.XDG_DATA_HOME || Path.join(process.env.HOME as string, '.local', 'share');
  if (folderExists(dataDir)) {
    dataDir = Path.resolve(Path.join(dataDir, pkgJSON.name, 'storage'));
    return defaultConfig.replace(/^storage: .\/storage$/m, `storage: ${dataDir}`);
  }
  return defaultConfig;
}

function getConfigPaths(): SetupDirectory[] {
  const listPaths: SetupDirectory[] = [
    getXDGDirectory(),
    getWindowsDirectory(),
    getRelativeDefaultDirectory(),
    getOldDirectory(),
  ].reduce(function (acc, currentValue: any): SetupDirectory[] {
    if (_.isUndefined(currentValue) === false) {
      acc.push(currentValue);
    }
    return acc;
  }, [] as SetupDirectory[]);

  return listPaths;
}

const getXDGDirectory = (): SetupDirectory | void => {
  const XDGConfig = getXDGHome() || (process.env.HOME && Path.join(process.env.HOME, '.config'));

  if (XDGConfig && folderExists(XDGConfig)) {
    return {
      path: Path.join(XDGConfig, pkgJSON.name, CONFIG_FILE),
      type: XDG,
    };
  }
};

const getXDGHome = (): string | void => process.env.XDG_CONFIG_HOME;

const getWindowsDirectory = (): SetupDirectory | void => {
  if (process.platform === WIN32 && process.env.APPDATA && folderExists(process.env.APPDATA)) {
    return {
      path: Path.resolve(Path.join(process.env.APPDATA, pkgJSON.name, CONFIG_FILE)),
      type: WIN,
    };
  }
};

const getRelativeDefaultDirectory = (): SetupDirectory => {
  return {
    path: Path.resolve(Path.join('.', pkgJSON.name, CONFIG_FILE)),
    type: 'def',
  };
};

const getOldDirectory = (): SetupDirectory => {
  return {
    path: Path.resolve(Path.join('.', CONFIG_FILE)),
    type: 'old',
  };
};

export default findConfigFile;
