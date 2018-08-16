import multer from 'multer';
import path from 'path';
import { createFolderIfNotExists } from '../utils/fsHandler';

const storage = multer.diskStorage({
  async destination(req, res, cb) {
    const pathToDir = path.join(__dirname, `../${process.env.UPLOAD_FOLDER}`);
    await createFolderIfNotExists(pathToDir);
    cb(null, pathToDir);
  },
  filename(req, file, cb) {
    cb(null, `${Date.now()}_${file.originalname}`);
  },
});

const upload = multer({ storage });

const diskStorageSingle = upload.single('file');

export default diskStorageSingle;
