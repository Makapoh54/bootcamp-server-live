import jwt from 'jsonwebtoken';
import Logger from '../utils/logger';
import AppError from '../errors/AppError';
import * as UserModel from '../models/UserModel';

const logger = Logger('authenticate');

const jwtVerify = token =>
  new Promise(resolve => {
    jwt.verify(token, process.env.JWT_SECRET, (error, decodedToken) => {
      resolve(decodedToken);
    });
  });

const authenticate = async (req, res, next) => {
  const { authorization } = req.headers; // "Authorization: YWxhZGRpbjp"
  let token;
  if (authorization) {
    [, token] = authorization.split(' ');
  }

  if (token) {
    const decodedToken = await jwtVerify(token);

    if (decodedToken && decodedToken.data && decodedToken.data.username) {
      const { username } = decodedToken.data;
      const user = await UserModel.getUserByName(username);
      if (user) {
        logger.log('debug', `User: ${username} was successfully authenticated!`);
        req.user = user;
        return next();
      }
    }
    return next(new AppError('Token is invalid', 401));
  }
  return next(new AppError('Not token provided', 401));
};

export default authenticate;
