import express from 'express';

import asyncMiddleware from '../middlewares/asyncMiddleware';
import { register, logIn } from '../controllers/userController';

const router = express.Router();

router.post('/users', asyncMiddleware(register));
router.post('/session', asyncMiddleware(logIn));

export default router;
