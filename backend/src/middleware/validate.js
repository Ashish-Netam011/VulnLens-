/**
 * Middleware factory to validate a request against a Zod schema.
 * Validates req.body unless a source is provided.
 */
export function validate(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      });
    }
    req[source] = result.data;
    next();
  };
}
