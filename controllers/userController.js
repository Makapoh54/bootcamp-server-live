import Logger from '../utils/logger';
import * as UserModel from '../models/UserModel';

const logger = Logger('userController');

const register = async (req, res) => {
  logger.log('debug', `register: ${JSON.stringify(req.body)}`);
  await UserModel.save({
    username: req.body.username,
    email: req.body.email,
    reHashedPassword: req.body.hashedPassword,
  });
  res.status(200).send({ payload: { message: 'Successfully registered' } });
};

export { register };
