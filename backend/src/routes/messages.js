// routes/messages.js
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth');
const messagesController = require('../controllers/messagesController');

router.use(authenticate);

router.get('/:conversationId', messagesController.getMessages);
router.post('/', messagesController.sendMessage);
router.delete('/:messageId', messagesController.deleteMessage);

module.exports = router;
