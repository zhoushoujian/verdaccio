/* eslint-disable @typescript-eslint/no-var-requires */

require('@babel/register')({
  extensions: ['.ts', '.js'],
});
module.exports = require('./lib/environment');
