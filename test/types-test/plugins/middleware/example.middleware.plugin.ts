// this file is not aim to be tested, just to check typescript definitions

/* eslint-disable @typescript-eslint/no-unused-vars */

/* eslint-disable no-unused-vars */
import { IReadTarball, IUploadTarball } from '@verdaccio/streams';
import { Package } from '@verdaccio/types';
import {
  Config as AppConfig,
  IBasicAuth,
  IPluginMiddleware,
  IStorageManager,
  RemoteUser,
} from '@verdaccio/types';

import Config from '../../../../src/lib/config';
import { generatePackageTemplate } from '../../../../src/lib/storage-utils';
import { readFile } from '../../../functional/lib/test.utils';
import { generateVersion } from '../../../unit/__helper/utils';

const readMetadata = (fileName: string): Package =>
  JSON.parse(readFile(`../../unit/partials/${fileName}`).toString()) as Package;

export default class ExampleMiddlewarePlugin implements IPluginMiddleware<{}> {
  register_middlewares(app: any, auth: IBasicAuth<{}>, storage: IStorageManager<{}>): void {
    const remoteUser: RemoteUser = {
      groups: [],
      real_groups: [],
      name: 'test',
    };
    auth.authenticate('user', 'password', () => {});
    auth.allow_access({ packageName: 'packageName' }, remoteUser, () => {});
    auth.add_user('user', 'password', () => {});
    auth.aesEncrypt(Buffer.from('pass'));
    // storage
    storage.addPackage('name', generatePackageTemplate('test'), () => {});
    storage.addVersion('name', 'version', generateVersion('name', '1.0.0'), 'tag', () => {});
    storage.mergeTags('name', { latest: '1.0.0' }, () => {});
    storage.changePackage('name', readMetadata('metadata'), 'revision', () => {});
    storage.removePackage('name', () => {});
    storage.mergeTags('name', { latest: '1.0.0' }, () => {});
    storage.removeTarball('name', 'filename', 'revision', () => {});
    const config1: AppConfig = new Config({
      storage: './storage',
      self_path: '/home/sotrage',
    });
    const add: IUploadTarball = storage.addTarball('name', 'filename');
    storage.getTarball('name', 'filename');
    const read: IReadTarball = storage.getTarball('name', 'filename');
    const search: IReadTarball = storage.search('test', {});
  }
}
