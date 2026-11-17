// Vercel serverless entry: every path is handled by the gatekeeper.
module.exports = require("../gatekeeper").handler;
