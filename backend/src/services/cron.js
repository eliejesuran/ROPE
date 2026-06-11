const cron = require('node-cron');
const { pool } = require('../models/db');
const logger = require('./logger');

function startCronJobs() {
  // Every minute: erase content of messages past their TTL
  cron.schedule('* * * * *', async () => {
    try {
      const { rowCount } = await pool.query(
        `UPDATE messages SET ciphertext = '', iv = '', deleted_at = NOW()
         WHERE expires_at IS NOT NULL AND expires_at < NOW() AND deleted_at IS NULL`
      );
      if (rowCount > 0) logger.info('Purged expired messages', { count: rowCount });
    } catch (err) {
      logger.error('Cron: purge expired messages failed', { error: err.message });
    }
  });
}

module.exports = { startCronJobs };
