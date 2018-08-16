import Logger from '../utils/logger';
import * as MediaModel from '../models/MediaModel';

const logger = Logger('mediaController');

const uploadImage = async (req, res) => {
  logger.log('debug', 'Upload Image!');
  const { user } = req;
  const {
    file: { filename },
  } = req;

  const path = `/${process.env.UPLOAD_FOLDER}/${filename}`;
  const media = await MediaModel.save({
    username: user.username,
    path,
  });

  res.status(200).send({
    payload: {
      contentId: media.id,
      path,
    },
  });
};

export { uploadImage };
