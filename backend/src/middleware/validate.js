import { HttpError } from '../lib/errors.js';

export const validate = (schema, source = 'body') => (req, _res, next) => {
  const r = schema.safeParse(req[source]);
  if (!r.success) {
    const msg = r.error.issues.map((i) => `${i.path.join('.') || source}: ${i.message}`).join('; ');
    return next(new HttpError(400, 'validation_error', msg));
  }
  req[source] = r.data;
  next();
};
