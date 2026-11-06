const serverless = require('serverless-http');
const app = require('../../server/index');

// Express routes keep their original /api/... paths.
exports.handler = serverless(app, { binary: ['image/*'] });
