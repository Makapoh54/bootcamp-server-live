import Logger from '../utils/logger';

const logger = Logger('defaultErrorHandler');

const defaultErrorHandler = (error, req, res, next) => {
  logger.log('error', `${error.name}:${error.status} - ${error.message}`);
  res.status(error.status || 500).send({ error: error.message });
};

export default defaultErrorHandler;
