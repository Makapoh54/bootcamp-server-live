import express from 'express';

import { uploadImage, addPost, getAllPosts, getPostById } from '../controllers/mediaController';
import asyncMiddleware from '../middlewares/asyncMiddleware';
import diskStorageSingle from '../middlewares/diskStorage';
import authenticate from '../middlewares/authenticate';

const router = express.Router();

router.post('/content/image', authenticate, diskStorageSingle, asyncMiddleware(uploadImage));
router.post('/media', authenticate, asyncMiddleware(addPost));
router.get('/media', authenticate, asyncMiddleware(getAllPosts));
router.get('/media/:id', authenticate, asyncMiddleware(getPostById));

export default router;
