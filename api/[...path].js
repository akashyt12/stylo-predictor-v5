const app = require('../server');

// Vercel Node runtime expects a plain (req, res) request handler.
module.exports = (req, res) => {
  app(req, res);
};
