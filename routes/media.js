import express from 'express';

import { uploadImage } from '../controllers/mediaController';
import diskStorageSingle from '../middlewares/diskStorage';
import authenticate from '../middlewares/authenticate';

const router = express.Router();

router.post('/content/image', authenticate, diskStorageSingle, uploadImage);

export default router;
