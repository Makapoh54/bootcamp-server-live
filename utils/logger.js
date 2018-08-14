import { createLogger, format, transports } from 'winston';

const { combine, timestamp, label, printf, colorize, align } = format;

const logsFormat = printf(info => `${info.timestamp} ${info.level} ${info.label}: ${info.message}`);

const Logger = location => {
  const consoleLogger = new transports.Console({
    level: 'info',
    format: combine(colorize(), timestamp(), align(), label({ label: location }), logsFormat),
  });
  const fileLogger = new transports.File({
    filename: 'logs/combined.log',
    level: 'debug',
    format: combine(colorize(), timestamp(), align(), label({ label: location }), logsFormat),
  });
  const logger = createLogger({ transports: [consoleLogger, fileLogger] });
  return logger;
};

export default Logger;

// const levels = {
//     error: 0,
//     warn: 1,
//     info: 2,
//     verbose: 3,
//     debug: 4,
//     silly: 5
//   };
