import Logger from '../utils/logger';

const logger = Logger('indexController');

const index = async (req, res) => {
  logger.log('info', 'Index controller was called');
  res.status(200).send({ message: 'Hello World' });
};

export default index;
