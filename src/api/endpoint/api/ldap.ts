import * as ldap from 'ldapjs';
import * as crypto from 'crypto';
import { $RequestExtend } from '../../../types';

export const verifyLdapUser = (username: string, password: string, req: $RequestExtend) => {
  if (!username || !password) {
    return Promise.resolve(false);
  }
  return new Promise((res, rej) => {
    const client = ldap.createClient({
      url: 'ldap://ldap.shuyun.com:389/',
    });
    return client.bind('cn=autotest,ou=people,dc=shuyun,dc=com', 'Shuyun789', function (err: Error | null) {
      if (err) {
        req.logger.error('ldap client.bind err', err);
        return rej(err);
      } else {
        const opts: any = {
          filter: `(uid=${username})`, //查询条件过滤器，查找uid=shoujian.zhou的用户节点
          scope: 'sub', //查询范围
          timeLimit: 500, //查询超时
        };
        return client.search('DC=shuyun,DC=com', opts, function (_err, response) {
          let searchSuccess = false;
          response.on('searchEntry', function (entry) {
            searchSuccess = true;
            const user = entry.object;
            const realPasswd = user.userPassword;
            if (!realPasswd || typeof realPasswd !== 'string') {
              return res(false);
            } else {
              const reg = /^\{(\w+)\}/;
              const temp = reg.exec(realPasswd);
              if (temp !== null) {
                const hashType = temp[1];
                const raw = realPasswd.replace(temp[0], '');
                // 将加密后的字符串base64解码， 注意，不要转为字符串，因为salt长度为4个字节，但转为字符串后长度不一定为4
                const decoded64 = Buffer.from(raw, 'base64');
                let cipher = 'sha1';
                switch (hashType) {
                  case 'SHA':
                  case 'SSHA':
                    cipher = 'sha1';
                    break;
                  case 'SHA256':
                  case 'SSHA256':
                    cipher = 'sha256';
                    break;
                  case 'SHA384':
                  case 'SSHA384':
                    cipher = 'sha384';
                    break;
                  case 'SHA512':
                  case 'SSHA512':
                    cipher = 'sha512';
                    break;
                  default:
                    break;
                }
                const serverPwd = decoded64.slice(0, 20);
                // 20位之后的为随机明文 salt(盐)，长度为4位
                const salt = decoded64.slice(20, decoded64.length);
                // 加盐干扰：计算 inputPwd = SHA1(input+salt), 普通哈希：计算 inputPwd = SHA1(input)
                const inputData = ['SHA', 'SHA256', 'SHA384', 'SHA512'].includes(cipher)
                  ? Buffer.from(password)
                  : Buffer.concat([Buffer.from(password), salt]);
                const inputPwd = Buffer.from(crypto.createHash(cipher).update(inputData).digest('base64'), 'base64');
                const verify = serverPwd.toString('ascii') === inputPwd.toString('ascii');
                if (verify) {
                  return res(user);
                } else {
                  return res(false);
                }
              } else {
                // 明文密码
                req.logger.info('verifyLdapUser 明文密码', realPasswd, user.cn);
                const verify = realPasswd === password;
                if (verify) {
                  return res(user);
                } else {
                  return res(false);
                }
              }
            }
          });

          response.on('searchReference', function (referral) {
            req.logger.info('verifyLdapUser searchReference referral: ' + referral.uris.join());
          });

          //查询错误事件
          response.on('error', function (err) {
            const content = `ldap client.search error 详细：${err.message || err.toString()}`;
            req.logger.error('ldap search content', content)
            searchSuccess = false;
            req.logger.error('verifyLdapUser response.on error: ' + err.message, 'username', username);
            client.unbind();
            return rej(err);
          });

          response.on('end', function () {
            client.unbind();
            if (searchSuccess === false) {
              req.logger.info('verifyLdapUser verify failed, username', username);
            }
            return res(false);
          });
        });
      }
    });
  });
};
