const target = process.env.API_PROXY_TARGET ?? 'http://localhost:8000';

module.exports = {
  '/api': {
    target,
    secure: false,
  },
};
