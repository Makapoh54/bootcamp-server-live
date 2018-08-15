import express from 'express';

import asyncMiddleware from '../middlewares/asyncMiddleware';
import { register } from '../controllers/userController';

const router = express.Router();

router.post('/users', asyncMiddleware(register));

export default router;
