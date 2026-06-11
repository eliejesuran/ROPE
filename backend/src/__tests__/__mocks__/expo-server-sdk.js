class Expo {
  static isExpoPushToken(token) {
    return typeof token === 'string' && token.startsWith('ExponentPushToken[');
  }
  chunkPushNotifications(messages) { return [messages]; }
  async sendPushNotificationsAsync(chunk) {
    return chunk.map(() => ({ status: 'ok' }));
  }
}

module.exports = { Expo };
