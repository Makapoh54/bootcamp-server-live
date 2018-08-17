import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import mongo from 'connect-mongo';
import mongoose from 'mongoose';
import './utils/dotenv';
import Logger from './utils/logger';
import defaultErrorHandler from './middlewares/defaultErrorHandler';

import index from './routes/index';
import user from './routes/user';
import media from './routes/media';

const logger = Logger('server.js');

const app = express();

const MongoStore = mongo(session);
mongoose.Promise = global.Promise;
mongoose.connect(
  process.env.MONGODB_URI,
  { useNewUrlParser: true },
);
mongoose.connection.on('error', () => {
  logger.log('error', 'Mongodb connection error. Please make sure MongoDB is running.');
  process.exit();
});
mongoose.connection.once('open', () => {
  logger.log('info', 'MongoDB has been connected');
});

app.use(bodyParser.json());
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    store: new MongoStore({
      url: process.env.MONGODB_URI,
      autoReconnect: true,
    }),
  }),
);

app.use(`/api/v${process.env.API_VERSION}`, index);
app.use(`/api/v${process.env.API_VERSION}`, user);
app.use(`/api/v${process.env.API_VERSION}`, media);

app.use(`/api/v${process.env.API_VERSION}/uploads`, express.static('uploads'));

app.use(defaultErrorHandler);

const host = process.env.HOST_ADDRESS;
const port = process.env.HOST_PORT;

app.listen(port, host, () => {
  console.log('ABC');
});
