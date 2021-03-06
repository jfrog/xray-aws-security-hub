import * as winston from 'winston';

const IS_DEVELOPMENT = process.env.NODE_ENV === 'development';
const MAX_LEVEL = process.env.MAX_LOG_LEVEL || (IS_DEVELOPMENT ? 'debug' : 'info');

export function getLogger(level = MAX_LEVEL) {
  const logger = winston.createLogger({
    level,
    format: winston.format.combine(
      winston.format.errors({ stack: process.env.NODE_ENV === 'development' }),
      winston.format.timestamp(),
      winston.format.splat(),
      winston.format.json(),
    ),
    transports: [
      new winston.transports.Console(),
    ],
  });

  return logger;
}
