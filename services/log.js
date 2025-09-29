const winston = require('winston');
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({filename:'http log',level:'http'}),
    new winston.transports.File({filename: 'warn log', level: 'warn'}),
    
    
  ],
});

module.exports = logger;