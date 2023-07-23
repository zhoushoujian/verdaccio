import { fork } from 'child_process';
import _ from 'lodash';
import path from 'path';
import rimRaf from 'rimraf';

import { HTTP_STATUS } from '../../src/lib/constants';
import { CREDENTIALS } from '../functional/config.functional';
import { IServerBridge, IServerProcess, IVerdaccioConfig } from '../types';

export default class VerdaccioProcess implements IServerProcess {
  private bridge: IServerBridge;
  private config: IVerdaccioConfig;
  private childFork: any;
  private isDebug: boolean;
  private silence: boolean;
  private cleanStore: boolean;

  public constructor(
    config: IVerdaccioConfig,
    bridge: IServerBridge,
    silence = true,
    isDebug = false,
    cleanStore = true
  ) {
    this.config = config;
    this.bridge = bridge;
    this.silence = silence;
    this.isDebug = isDebug;
    this.cleanStore = cleanStore;
  }

  public init(verdaccioPath = '../../bin/verdaccio'): Promise<any> {
    return new Promise((resolve, reject) => {
      if (this.cleanStore) {
        rimRaf(this.config.storagePath, (err) => {
          if (_.isNil(err) === false) {
            reject(err);
          }

          this._start(verdaccioPath, resolve, reject);
        });
      } else {
        this._start(verdaccioPath, resolve, reject);
      }
    });
  }

  private _start(verdaccioPath: string, resolve: Function, reject: Function) {
    const verdaccioRegisterWrap: string = path.join(__dirname, verdaccioPath);
    let childOptions = {
      silent: false,
    };

    if (this.isDebug) {
      // @ts-ignore
      const debugPort = parseInt(this.config.port, 10) + 5;

      childOptions = Object.assign({}, childOptions, {
        execArgv: [`--inspect=${debugPort}`],
      });
    }

    const { configPath, port } = this.config;
    this.childFork = fork(
      verdaccioRegisterWrap,
      ['-c', configPath, '-l', port as string],
      childOptions
    );

    this.childFork.on('message', (msg) => {
      // verdaccio_started is a message that comes from verdaccio in debug mode that notify has been started
      if ('verdaccio_started' in msg) {
        this.bridge
          .debug()
          .status(HTTP_STATUS.OK)
          .then((body) => {
            this.bridge
              .auth(CREDENTIALS.user, CREDENTIALS.password)
              .status(HTTP_STATUS.CREATED)
              .body_ok(new RegExp(CREDENTIALS.user))
              .then(() => resolve([this, body.pid]), reject);
          }, reject);
      }
    });

    this.childFork.on('error', (err) => reject([err, this]));
    this.childFork.on('disconnect', (err) => reject([err, this]));
    this.childFork.on('exit', (err) => reject([err, this]));
  }

  public stop(): void {
    return this.childFork.kill('SIGINT');
  }
}
