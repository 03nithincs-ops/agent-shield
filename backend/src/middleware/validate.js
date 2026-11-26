function validate(schema) {
  return (req, res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: error.errors ? error.errors.map(e => ({ field: e.path.join('.'), message: e.message })) : error.message
      });
    }
  };
}

module.exports = validate;
