import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, FlatList, TextInput, TouchableOpacity,
  StyleSheet, KeyboardAvoidingView, Platform, Alert,
  ActivityIndicator,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { api } from '../services/api';
import { useAuth } from '../services/authContext';
import {
  encryptMessage, decryptMessage,
  generateConversationKey, storeConversationKey, getConversationKey,
} from '../services/crypto';
import { onNewMessage, offNewMessage, getSocket } from '../services/socket';

interface Message {
  id: string;
  sender_id: string;
  ciphertext: string;
  iv: string;
  sent_at: string;
  plaintext?: string; // decrypted locally, never sent to server
  error?: boolean;
}

interface Props {
  conversation: {
    conversation_id: string;
    contact_id: string;
    display_name: string | null;
    phone_last4: string;
    public_key: string;
  };
  onBack: () => void;
}

export default function ChatScreen({ conversation, onBack }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [hasKey, setHasKey] = useState(false);
  const [sharedKey, setSharedKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const flatListRef = useRef<FlatList>(null);

  const convId = conversation.conversation_id;

  // ── Decrypt a single message ────────────────────────────────────────────────
  const decrypt = async (msg: Message): Promise<Message> => {
    try {
      const plaintext = await decryptMessage(msg.ciphertext, msg.iv, convId);
      return { ...msg, plaintext };
    } catch {
      return { ...msg, plaintext: '[Message illisible — clé manquante?]', error: true };
    }
  };

  // ── Load messages ────────────────────────────────────────────────────────────
  const loadMessages = useCallback(async () => {
    try {
      const { messages: raw } = await api.messages.get(convId);
      const decrypted = await Promise.all(raw.map(decrypt));
      setMessages(decrypted);
    } catch (err: any) {
      console.error('Failed to load messages', err.message);
    } finally {
      setLoading(false);
    }
  }, [convId]);

  // ── Check for conversation key ───────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      const key = await getConversationKey(convId);
      if (key) {
        setHasKey(true);
        setSharedKey(key);
      }
      await loadMessages();
    })();

    // New message via WebSocket
    onNewMessage(async (msg: any) => {
      if (msg.conversationId !== convId) return;
      const decrypted = await decrypt(msg);
      setMessages(prev => [...prev, decrypted]);
      // Mark as read
      getSocket()?.emit('message:read', { messageId: msg.id, conversationId: convId });
    });

    return () => offNewMessage();
  }, [convId]);

  // ── Generate + display a new shared key ─────────────────────────────────────
  const handleGenerateKey = async () => {
    const key = await generateConversationKey();
    await storeConversationKey(convId, key);
    setSharedKey(key);
    setHasKey(true);
    Alert.alert(
      '🔑 Clé de conversation générée',
      `Partagez cette clé avec votre contact par un canal sécurisé (en personne, ou par appel vocal) :\n\n${key}\n\nVotre contact devra la saisir dans "Entrer une clé".`,
      [{ text: 'OK' }]
    );
  };

  const handleEnterKey = () => {
    Alert.prompt(
      '🔑 Entrer la clé partagée',
      'Collez la clé que votre contact vous a envoyée :',
      async (key) => {
        if (!key?.trim()) return;
        await storeConversationKey(convId, key.trim());
        setSharedKey(key.trim());
        setHasKey(true);
        // Re-decrypt existing messages with new key
        await loadMessages();
      },
      'plain-text'
    );
  };

  // ── Send message ─────────────────────────────────────────────────────────────
  const handleSend = async () => {
    if (!input.trim() || !hasKey || sending) return;
    const text = input.trim();
    setInput('');
    setSending(true);

    try {
      const { ciphertext, iv } = await encryptMessage(text, convId);
      const { id, sentAt } = await api.messages.send(convId, ciphertext, iv);

      // Optimistic update
      setMessages(prev => [...prev, {
        id,
        sender_id: user!.id,
        ciphertext,
        iv,
        sent_at: sentAt,
        plaintext: text,
      }]);

      setTimeout(() => flatListRef.current?.scrollToEnd({ animated: true }), 100);
    } catch (err: any) {
      Alert.alert('Échec', 'Message non envoyé : ' + err.message);
      setInput(text); // restore
    } finally {
      setSending(false);
    }
  };

  const renderMessage = ({ item }: { item: Message }) => {
    const isMine = item.sender_id === user?.id;
    return (
      <View style={[styles.bubble, isMine ? styles.bubbleMine : styles.bubbleTheirs]}>
        <Text style={[styles.bubbleText, item.error && styles.bubbleError]}>
          {item.plaintext ?? '…'}
        </Text>
        <Text style={styles.bubbleTime}>
          {new Date(item.sent_at).toLocaleTimeString('fr-BE', {
            hour: '2-digit', minute: '2-digit',
          })}
        </Text>
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={0}
    >
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn}>
          <Text style={styles.backText}>←</Text>
        </TouchableOpacity>
        <View style={styles.headerInfo}>
          <Text style={styles.headerName}>
            {conversation.display_name || `+·······${conversation.phone_last4}`}
          </Text>
          <Text style={styles.headerSub}>🔒 Chiffré de bout en bout</Text>
        </View>
        <TouchableOpacity onPress={hasKey ? handleEnterKey : handleGenerateKey}>
          <Text style={styles.keyBtn}>🔑</Text>
        </TouchableOpacity>
      </View>

      {/* No key banner */}
      {!hasKey && (
        <View style={styles.noBanner}>
          <Text style={styles.noBannerText}>
            Aucune clé de chiffrement pour cette conversation.
          </Text>
          <View style={styles.noBannerActions}>
            <TouchableOpacity style={styles.noBannerBtn} onPress={handleGenerateKey}>
              <Text style={styles.noBannerBtnText}>Générer une clé</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[styles.noBannerBtn, styles.noBannerBtnAlt]} onPress={handleEnterKey}>
              <Text style={styles.noBannerBtnText}>Entrer une clé</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      {/* Messages */}
      {loading
        ? <ActivityIndicator style={{ flex: 1 }} color="#4f9eff" />
        : (
          <FlatList
            ref={flatListRef}
            data={messages}
            keyExtractor={(item) => item.id}
            renderItem={renderMessage}
            contentContainerStyle={styles.messageList}
            onLayout={() => flatListRef.current?.scrollToEnd({ animated: false })}
          />
        )
      }

      {/* Input */}
      <View style={styles.inputBar}>
        <TextInput
          style={[styles.textInput, !hasKey && styles.textInputDisabled]}
          placeholder={hasKey ? 'Message…' : 'Échangez une clé d\'abord'}
          placeholderTextColor="#444"
          value={input}
          onChangeText={setInput}
          multiline
          editable={hasKey}
          onSubmitEditing={handleSend}
          blurOnSubmit={false}
        />
        <TouchableOpacity
          style={[styles.sendBtn, (!hasKey || !input.trim() || sending) && styles.sendBtnDisabled]}
          onPress={handleSend}
          disabled={!hasKey || !input.trim() || sending}
        >
          {sending
            ? <ActivityIndicator color="#fff" size="small" />
            : <Text style={styles.sendBtnText}>↑</Text>
          }
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a0a0f' },
  header: {
    flexDirection: 'row', alignItems: 'center',
    paddingTop: 60, paddingBottom: 14,
    paddingHorizontal: 16,
    borderBottomWidth: 1, borderBottomColor: '#1a1a2e',
    gap: 12,
  },
  backBtn: { padding: 4 },
  backText: { color: '#4f9eff', fontSize: 22 },
  headerInfo: { flex: 1 },
  headerName: { color: '#fff', fontSize: 16, fontWeight: '700' },
  headerSub: { color: '#3a7a3a', fontSize: 11, marginTop: 2 },
  keyBtn: { fontSize: 20 },
  noBanner: {
    backgroundColor: '#1a0f00', borderBottomWidth: 1,
    borderBottomColor: '#3a2000', padding: 16,
  },
  noBannerText: { color: '#f90', fontSize: 13, marginBottom: 10, textAlign: 'center' },
  noBannerActions: { flexDirection: 'row', gap: 10, justifyContent: 'center' },
  noBannerBtn: {
    backgroundColor: '#4f9eff', borderRadius: 8,
    paddingHorizontal: 16, paddingVertical: 8,
  },
  noBannerBtnAlt: { backgroundColor: '#2a3a5a' },
  noBannerBtnText: { color: '#fff', fontSize: 13, fontWeight: '600' },
  messageList: { padding: 16, paddingBottom: 8 },
  bubble: {
    maxWidth: '78%', borderRadius: 16,
    padding: 10, marginBottom: 8,
  },
  bubbleMine: {
    alignSelf: 'flex-end',
    backgroundColor: '#1a3a6a',
    borderBottomRightRadius: 4,
  },
  bubbleTheirs: {
    alignSelf: 'flex-start',
    backgroundColor: '#1a1a2e',
    borderBottomLeftRadius: 4,
  },
  bubbleText: { color: '#fff', fontSize: 15, lineHeight: 20 },
  bubbleError: { color: '#f66', fontStyle: 'italic' },
  bubbleTime: { color: '#555', fontSize: 10, marginTop: 4, textAlign: 'right' },
  inputBar: {
    flexDirection: 'row', alignItems: 'flex-end',
    padding: 12, gap: 8,
    borderTopWidth: 1, borderTopColor: '#1a1a2e',
    backgroundColor: '#0a0a0f',
  },
  textInput: {
    flex: 1, backgroundColor: '#161622',
    borderRadius: 20, paddingHorizontal: 16,
    paddingVertical: 10, color: '#fff',
    fontSize: 15, maxHeight: 120,
    borderWidth: 1, borderColor: '#2a2a40',
  },
  textInputDisabled: { opacity: 0.4 },
  sendBtn: {
    backgroundColor: '#4f9eff', width: 42, height: 42,
    borderRadius: 21, alignItems: 'center', justifyContent: 'center',
  },
  sendBtnDisabled: { backgroundColor: '#1a2a4a' },
  sendBtnText: { color: '#fff', fontSize: 18, fontWeight: '700' },
});
