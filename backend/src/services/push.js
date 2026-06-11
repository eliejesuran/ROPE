const { Expo } = require('expo-server-sdk');
const logger = require('./logger');

const expo = new Expo();

async function sendPushNotifications(tokens, { title, body, data = {} }) {
  const messages = tokens
    .filter(token => Expo.isExpoPushToken(token))
    .map(to => ({ to, sound: 'default', title, body, data }));

  if (messages.length === 0) return;

  const chunks = expo.chunkPushNotifications(messages);
  for (const chunk of chunks) {
    try {
      const receipts = await expo.sendPushNotificationsAsync(chunk);
      receipts.forEach(receipt => {
        if (receipt.status === 'error') {
          logger.warn('Push notification error', { message: receipt.message, details: receipt.details });
        }
      });
    } catch (err) {
      logger.error('Push send failed', { error: err.message });
    }
  }
}

module.exports = { sendPushNotifications };
