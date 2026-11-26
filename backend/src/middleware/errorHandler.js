function errorHandler(err, req, res, next) {
  console.error('[Error Handler]', err);

  const statusCode = err.statusCode || (res.statusCode === 200 ? 500 : res.statusCode);
  
  res.status(statusCode).json({
    success: false,
    error: err.message || 'Internal Server Error',
    stack: process.env.NODE_ENV === 'production' ? undefined : err.stack
  });
}

module.exports = errorHandler;
