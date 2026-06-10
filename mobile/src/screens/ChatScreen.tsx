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
  getConversationKey,
  x3dhInitiator, x3dhResponder,
} from '../services/crypto';
import { onNewMessage, offNewMessage, getSocket } from '../services/socket';

interface Message {
  id: string;
  sender_id: string;
  ciphertext: string;
  iv: string;
  sent_at: string;
  plaintext?: string;
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

type KeyStatus = 'establishing' | 'ready' | 'error';

export default function ChatScreen({ conversation, onBack }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [hasKey, setHasKey] = useState(false);
  const [keyStatus, setKeyStatus] = useState<KeyStatus>('establishing');
  const [loading, setLoading] = useState(true);
  const flatListRef = useRef<FlatList>(null);
  const convId = conversation.conversation_id;

  const decrypt = async (msg: Message): Promise<Message> => {
    try {
      const plaintext = await decryptMessage(msg.ciphertext, msg.iv, convId);
      return { ...msg, plaintext };
    } catch {
      return { ...msg, plaintext: '[Clé incorrecte ou manquante]', error: true };
    }
  };

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

  // ── Auto-establish X3DH session ───────────────────────────────────────────
  useEffect(() => {
    (async () => {
      // If a key already exists (prior session or manual), use it directly
      const existing = await getConversationKey(convId);
      if (existing) {
        setHasKey(true);
        setKeyStatus('ready');
        await loadMessages();
        return;
      }

      setKeyStatus('establishing');
      try {
        // Try as responder first: check if the other party already posted X3DH init
        let initData: { ikPub: string; ekPub: string; opkId: number | null } | null = null;
        try {
          initData = await api.keys.getX3DHInit(convId);
        } catch {
          // 404 or 403 — no init exists yet, we become the initiator
        }

        if (initData) {
          await x3dhResponder(convId, initData);
        } else {
          // Become the initiator: fetch contact's key bundle and run X3DH
          const bundle = await api.keys.getBundle(conversation.contact_id);
          const myIkPub = (await SecureStore.getItemAsync('ik_pub'))!;
          const { ekPub, opkId } = await x3dhInitiator(convId, bundle);

          try {
            await api.keys.postX3DHInit(convId, { ikPub: myIkPub, ekPub, opkId });
          } catch (err: any) {
            if (err.message === 'X3DH init already exists') {
              // Race: the other party posted first — re-fetch and become responder
              const lateInit = await api.keys.getX3DHInit(convId);
              await x3dhResponder(convId, lateInit);
            } else {
              throw err;
            }
          }
        }

        setHasKey(true);
        setKeyStatus('ready');
      } catch (err: any) {
        console.error('[X3DH] Session establishment failed', err.message);
        setKeyStatus('error');
      }

      await loadMessages();
    })();

    onNewMessage(async (msg: any) => {
      if (msg.conversationId !== convId) return;
      const normalised = { ...msg, sent_at: msg.sentAt || msg.sent_at };
      const decrypted = await decrypt(normalised);
      setMessages(prev => [...prev, decrypted]);
      getSocket()?.emit('message:read', { messageId: msg.id, conversationId: convId });
      setTimeout(() => flatListRef.current?.scrollToEnd({ animated: true }), 100);
    });

    return () => offNewMessage();
  }, [convId]);

  // ── Send message ──────────────────────────────────────────────────────────
  const handleSend = async () => {
    if (!input.trim() || !hasKey || sending) return;
    const text = input.trim();
    setInput('');
    setSending(true);
    try {
      const { ciphertext, iv } = await encryptMessage(text, convId);
      const { id, sentAt } = await api.messages.send(convId, ciphertext, iv);
      setMessages(prev => [...prev, {
        id, sender_id: user!.id,
        ciphertext, iv, sent_at: sentAt, plaintext: text,
      }]);
      setTimeout(() => flatListRef.current?.scrollToEnd({ animated: true }), 100);
    } catch (err: any) {
      Alert.alert('Échec', err.message);
      setInput(text);
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
          {new Date(item.sent_at).toLocaleTimeString('fr-BE', { hour: '2-digit', minute: '2-digit' })}
        </Text>
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
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
          <Text style={styles.headerSub}>
            {keyStatus === 'establishing' ? '🔄 Chiffrement en cours…'
              : keyStatus === 'error'       ? '⚠️ Chiffrement non établi'
              :                              '🔒 Chiffré de bout en bout'}
          </Text>
        </View>
        {keyStatus === 'establishing' && (
          <ActivityIndicator color="#4f9eff" size="small" style={{ marginRight: 4 }} />
        )}
      </View>

      {/* Statut clé */}
      {keyStatus === 'establishing' && (
        <View style={styles.statusBanner}>
          <Text style={styles.statusText}>
            Établissement du chiffrement de bout en bout…
          </Text>
        </View>
      )}
      {keyStatus === 'error' && (
        <View style={[styles.statusBanner, styles.statusBannerError]}>
          <Text style={styles.statusText}>
            Impossible d'établir le chiffrement. Demandez à votre contact de rouvrir l'app.
          </Text>
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
          placeholder={
            keyStatus === 'establishing' ? 'Chiffrement en cours…'
            : keyStatus === 'error'       ? 'Chiffrement non disponible'
            :                              'Message…'
          }
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
    paddingTop: 60, paddingBottom: 14, paddingHorizontal: 16,
    borderBottomWidth: 1, borderBottomColor: '#1a1a2e', gap: 12,
  },
  backBtn: { padding: 4 },
  backText: { color: '#4f9eff', fontSize: 22 },
  headerInfo: { flex: 1 },
  headerName: { color: '#fff', fontSize: 16, fontWeight: '700' },
  headerSub: { color: '#3a7a3a', fontSize: 11, marginTop: 2 },
  statusBanner: {
    backgroundColor: '#0f1a2e', borderBottomWidth: 1,
    borderBottomColor: '#1a2a4a', padding: 12,
  },
  statusBannerError: { backgroundColor: '#1a0f00', borderBottomColor: '#3a2000' },
  statusText: { color: '#aaa', fontSize: 12, textAlign: 'center', lineHeight: 17 },
  messageList: { padding: 16, paddingBottom: 8 },
  bubble: { maxWidth: '78%', borderRadius: 16, padding: 10, marginBottom: 8 },
  bubbleMine: { alignSelf: 'flex-end', backgroundColor: '#1a3a6a', borderBottomRightRadius: 4 },
  bubbleTheirs: { alignSelf: 'flex-start', backgroundColor: '#1a1a2e', borderBottomLeftRadius: 4 },
  bubbleText: { color: '#fff', fontSize: 15, lineHeight: 20 },
  bubbleError: { color: '#f66', fontStyle: 'italic' },
  bubbleTime: { color: '#555', fontSize: 10, marginTop: 4, textAlign: 'right' },
  inputBar: {
    flexDirection: 'row', alignItems: 'flex-end',
    padding: 12, gap: 8,
    borderTopWidth: 1, borderTopColor: '#1a1a2e', backgroundColor: '#0a0a0f',
  },
  textInput: {
    flex: 1, backgroundColor: '#161622', borderRadius: 20,
    paddingHorizontal: 16, paddingVertical: 10, color: '#fff',
    fontSize: 15, maxHeight: 120, borderWidth: 1, borderColor: '#2a2a40',
  },
  textInputDisabled: { opacity: 0.4 },
  sendBtn: {
    backgroundColor: '#4f9eff', width: 42, height: 42,
    borderRadius: 21, alignItems: 'center', justifyContent: 'center',
  },
  sendBtnDisabled: { backgroundColor: '#1a2a4a' },
  sendBtnText: { color: '#fff', fontSize: 18, fontWeight: '700' },
});
