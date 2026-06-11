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
  hasDRState, drCanSend, drEncrypt, drDecrypt, initDRFromExistingSession,
  type DRHeader,
} from '../services/crypto';
import { onNewMessage, offNewMessage, getSocket } from '../services/socket';

const TTL_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: '∞', value: null },
  { label: '1h', value: 3600 },
  { label: '24h', value: 86400 },
  { label: '7j', value: 604800 },
];

interface Message {
  id: string;
  sender_id: string;
  ciphertext: string;
  iv: string;
  ratchet_header?: string | null;
  sent_at: string;
  expires_at?: string | null;
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

function formatExpiry(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return 'expiré';
  const secs = Math.floor(ms / 1000);
  if (secs < 3600) return `${Math.floor(secs / 60)}min`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}j`;
}

export default function ChatScreen({ conversation, onBack }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [ttlIndex, setTtlIndex] = useState(0);
  const [keyStatus, setKeyStatus] = useState<KeyStatus>('establishing');
  const [drReady, setDrReady] = useState(false);   // true when CKs exists (can send)
  const [loading, setLoading] = useState(true);
  const flatListRef = useRef<FlatList>(null);
  const convId = conversation.conversation_id;

  // Decrypt one message — uses DR if ratchet_header present, legacy otherwise
  const decrypt = useCallback(async (msg: Message): Promise<Message> => {
    try {
      let plaintext: string;
      if (msg.ratchet_header) {
        const header: DRHeader = JSON.parse(msg.ratchet_header);
        plaintext = await drDecrypt(convId, msg.ciphertext, msg.iv, header);
        // After DR decrypt, the responder may now have a sending chain
        const canSend = await drCanSend(convId);
        setDrReady(canSend);
      } else {
        plaintext = await decryptMessage(msg.ciphertext, msg.iv, convId);
      }
      return { ...msg, plaintext };
    } catch {
      return { ...msg, plaintext: '[Clé incorrecte ou manquante]', error: true };
    }
  }, [convId]);

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
  }, [convId, decrypt]);

  // ── Session establishment (X3DH + DR) ────────────────────────────────────
  useEffect(() => {
    (async () => {
      const existingKey = await getConversationKey(convId);

      if (existingKey) {
        // Session key exists — check if DR state is also present
        if (await hasDRState(convId)) {
          const canSend = await drCanSend(convId);
          setDrReady(canSend);
          setKeyStatus('ready');
          await loadMessages();
          return;
        }

        // Sprint-2 session exists but no DR state — migrate to Double Ratchet
        setKeyStatus('establishing');
        try {
          let initData: { initiatorId: string; ikPub: string; ekPub: string; opkId: number | null } | null = null;
          try { initData = await api.keys.getX3DHInit(convId); } catch { /* no init yet */ }

          if (initData && initData.initiatorId === user!.id) {
            const bundle = await api.keys.getBundle(conversation.contact_id);
            await initDRFromExistingSession(convId, 'initiator', bundle.spkPub);
          } else {
            await initDRFromExistingSession(convId, 'responder');
          }
          setDrReady(await drCanSend(convId));
          setKeyStatus('ready');
        } catch (err: any) {
          console.error('[DR migration] Failed', err.message);
          setKeyStatus('error');
        }
        await loadMessages();
        return;
      }

      // No session at all — run X3DH to establish one
      setKeyStatus('establishing');
      try {
        let initData: { initiatorId: string; ikPub: string; ekPub: string; opkId: number | null } | null = null;
        try { initData = await api.keys.getX3DHInit(convId); } catch { /* no init yet */ }

        if (initData) {
          // Become responder: the other party already posted the X3DH init
          await x3dhResponder(convId, initData);
        } else {
          // Become initiator: fetch contact's bundle and post the X3DH init
          const bundle   = await api.keys.getBundle(conversation.contact_id);
          const myIkPub  = (await SecureStore.getItemAsync('ik_pub'))!;
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

        setDrReady(await drCanSend(convId));
        setKeyStatus('ready');
      } catch (err: any) {
        console.error('[X3DH] Session establishment failed', err.message);
        setKeyStatus('error');
      }

      await loadMessages();
    })();

    onNewMessage(async (msg: any) => {
      if (msg.conversationId !== convId) return;
      const normalised: Message = {
        id:             msg.id,
        sender_id:      msg.senderId || msg.sender_id,
        ciphertext:     msg.ciphertext,
        iv:             msg.iv,
        ratchet_header: msg.ratchetHeader ?? msg.ratchet_header ?? null,
        sent_at:        msg.sentAt || msg.sent_at,
        expires_at:     msg.expiresAt ?? msg.expires_at ?? null,
      };
      const decrypted = await decrypt(normalised);
      setMessages(prev => [...prev, decrypted]);
      getSocket()?.emit('message:read', { messageId: msg.id, conversationId: convId });
      setTimeout(() => flatListRef.current?.scrollToEnd({ animated: true }), 100);
    });

    return () => offNewMessage();
  }, [convId]);

  // ── Send message ──────────────────────────────────────────────────────────
  const handleSend = async () => {
    if (!input.trim() || !drReady || sending) return;
    const text = input.trim();
    setInput('');
    setSending(true);
    try {
      const { ciphertext, iv, header } = await drEncrypt(convId, text);
      const ratchetHeader = JSON.stringify(header);
      const expiresIn = TTL_OPTIONS[ttlIndex].value;
      const { id, sentAt, expiresAt } = await api.messages.send(convId, ciphertext, iv, ratchetHeader, expiresIn);
      setMessages(prev => [...prev, {
        id, sender_id: user!.id,
        ciphertext, iv, ratchet_header: ratchetHeader, sent_at: sentAt,
        expires_at: expiresAt, plaintext: text,
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
    const expiryLabel = item.expires_at ? formatExpiry(item.expires_at) : null;
    return (
      <View style={[styles.bubble, isMine ? styles.bubbleMine : styles.bubbleTheirs]}>
        <Text style={[styles.bubbleText, item.error && styles.bubbleError]}>
          {item.plaintext ?? '…'}
        </Text>
        <View style={styles.bubbleMeta}>
          <Text style={styles.bubbleTime}>
            {new Date(item.sent_at).toLocaleTimeString('fr-BE', { hour: '2-digit', minute: '2-digit' })}
          </Text>
          {expiryLabel && (
            <Text style={styles.bubbleExpiry}>🔥 {expiryLabel}</Text>
          )}
        </View>
      </View>
    );
  };

  const isEstablished = keyStatus === 'ready';
  const canTypeAndSend = isEstablished && drReady;

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
              : keyStatus === 'error'      ? '⚠️ Chiffrement non établi'
              : !drReady                   ? '⏳ En attente du premier message…'
              :                             '🔒 Chiffré de bout en bout (Double Ratchet)'}
          </Text>
        </View>
        {keyStatus === 'establishing' && (
          <ActivityIndicator color="#4f9eff" size="small" style={{ marginRight: 4 }} />
        )}
      </View>

      {/* Statut */}
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
      {isEstablished && !drReady && (
        <View style={styles.statusBanner}>
          <Text style={styles.statusText}>
            En attente du premier message de votre contact pour activer l'envoi.
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
        <TouchableOpacity
          style={styles.ttlBtn}
          onPress={() => setTtlIndex(i => (i + 1) % TTL_OPTIONS.length)}
          disabled={!canTypeAndSend}
        >
          <Text style={[styles.ttlText, TTL_OPTIONS[ttlIndex].value && styles.ttlActive]}>
            {TTL_OPTIONS[ttlIndex].value ? `🔥${TTL_OPTIONS[ttlIndex].label}` : '∞'}
          </Text>
        </TouchableOpacity>
        <TextInput
          style={[styles.textInput, !canTypeAndSend && styles.textInputDisabled]}
          placeholder={
            keyStatus === 'establishing' ? 'Chiffrement en cours…'
            : keyStatus === 'error'       ? 'Chiffrement non disponible'
            : !drReady                    ? 'En attente du premier message…'
            :                              'Message…'
          }
          placeholderTextColor="#444"
          value={input}
          onChangeText={setInput}
          multiline
          editable={canTypeAndSend}
          onSubmitEditing={handleSend}
          blurOnSubmit={false}
        />
        <TouchableOpacity
          style={[styles.sendBtn, (!canTypeAndSend || !input.trim() || sending) && styles.sendBtnDisabled]}
          onPress={handleSend}
          disabled={!canTypeAndSend || !input.trim() || sending}
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
  bubbleMeta: { flexDirection: 'row', justifyContent: 'flex-end', alignItems: 'center', gap: 6, marginTop: 4 },
  bubbleTime: { color: '#555', fontSize: 10 },
  bubbleExpiry: { color: '#c65', fontSize: 10 },
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
  ttlBtn: {
    width: 36, height: 36, borderRadius: 10,
    backgroundColor: '#161622', borderWidth: 1, borderColor: '#2a2a40',
    alignItems: 'center', justifyContent: 'center',
  },
  ttlText: { color: '#555', fontSize: 12, fontWeight: '600' },
  ttlActive: { color: '#c65' },
});
