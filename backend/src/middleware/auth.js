import { HttpError } from '../lib/errors.js';

export const requireAuth = (auth) => (req, _res, next) => {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  const user = m && auth.verifyAccessToken(m[1]);
  if (!user) return next(new HttpError(401, 'unauthorized', 'Требуется авторизация'));
  req.user = user;
  next();
};
