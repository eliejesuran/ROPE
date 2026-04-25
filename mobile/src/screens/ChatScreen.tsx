import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, FlatList, TextInput, TouchableOpacity,
  StyleSheet, KeyboardAvoidingView, Platform, Alert,
  ActivityIndicator,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
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

export default function ChatScreen({ conversation, onBack }: Props) {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [hasKey, setHasKey] = useState(false);
  const [loading, setLoading] = useState(true);
  const [isInitiator, setIsInitiator] = useState(false);
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

  useEffect(() => {
    (async () => {
      const key = await getConversationKey(convId);
      if (key) setHasKey(true);
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

  // ── Clé : A génère et partage ─────────────────────────────────────────────
  const handleGenerateAndShare = async () => {
    const key = await generateConversationKey();
    await storeConversationKey(convId, key);
    setHasKey(true);
    setIsInitiator(true);
    await Clipboard.setStringAsync(key);
    await loadMessages();

    Alert.alert(
      '🔑 Clé copiée !',
      'La clé est dans votre presse-papier.\n\nEnvoyez-la à votre contact (Signal, SMS, appel…).\n\nIl devra appuyer sur "J\'ai reçu une clé" et coller.',
      [
        { text: 'Copier à nouveau', onPress: () => Clipboard.setStringAsync(key) },
        { text: 'OK', style: 'default' },
      ]
    );
  };

  // ── Clé : B entre la clé reçue ────────────────────────────────────────────
  const handleEnterReceivedKey = () => {
    Alert.prompt(
      '🔑 Coller la clé reçue',
      'Collez la clé que votre contact vous a envoyée :',
      async (key) => {
        if (!key?.trim()) return;
        await storeConversationKey(convId, key.trim());
        setHasKey(true);
        setIsInitiator(false);
        await loadMessages();
        Alert.alert('✅ Clé enregistrée', 'Vous pouvez maintenant lire et envoyer des messages.');
      },
      'plain-text'
    );
  };

  // ── Régénérer la clé (si ça n'a pas marché) ──────────────────────────────
  const handleKeyMenu = () => {
    Alert.alert(
      '🔑 Gestion de la clé',
      'Que souhaitez-vous faire ?',
      [
        {
          text: 'Régénérer une nouvelle clé',
          onPress: () => {
            Alert.alert(
              'Régénérer ?',
              'Attention : les anciens messages ne seront plus lisibles. Continuer ?',
              [
                { text: 'Annuler', style: 'cancel' },
                { text: 'Régénérer', style: 'destructive', onPress: handleGenerateAndShare },
              ]
            );
          },
        },
        { text: 'Entrer une clé reçue', onPress: handleEnterReceivedKey },
        { text: 'Copier la clé actuelle', onPress: async () => {
          const key = await getConversationKey(convId);
          if (key) {
            await Clipboard.setStringAsync(key);
            Alert.alert('📋 Copié', 'Clé copiée dans le presse-papier.');
          } else {
            Alert.alert('Aucune clé', 'Pas de clé enregistrée pour cette conversation.');
          }
        }},
        { text: 'Annuler', style: 'cancel' },
      ]
    );
  };

  // ── Envoyer un message ────────────────────────────────────────────────────
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
          <Text style={styles.headerSub}>🔒 Chiffré de bout en bout</Text>
        </View>
        <TouchableOpacity onPress={handleKeyMenu} style={styles.keyBtnWrap}>
          <Text style={styles.keyBtn}>🔑</Text>
        </TouchableOpacity>
      </View>

      {/* Bannière si pas de clé */}
      {!hasKey && (
        <View style={styles.noBanner}>
          <Text style={styles.noBannerTitle}>Aucune clé de chiffrement</Text>
          <Text style={styles.noBannerText}>
            Pour commencer, une personne génère la clé et l'envoie à l'autre.
          </Text>
          <View style={styles.noBannerActions}>
            <TouchableOpacity style={styles.btnPrimary} onPress={handleGenerateAndShare}>
              <Text style={styles.btnText}>Je génère la clé</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btnSecondary} onPress={handleEnterReceivedKey}>
              <Text style={styles.btnText}>J'ai reçu une clé</Text>
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
    paddingTop: 60, paddingBottom: 14, paddingHorizontal: 16,
    borderBottomWidth: 1, borderBottomColor: '#1a1a2e', gap: 12,
  },
  backBtn: { padding: 4 },
  backText: { color: '#4f9eff', fontSize: 22 },
  headerInfo: { flex: 1 },
  headerName: { color: '#fff', fontSize: 16, fontWeight: '700' },
  headerSub: { color: '#3a7a3a', fontSize: 11, marginTop: 2 },
  keyBtnWrap: { padding: 4 },
  keyBtn: { fontSize: 22 },
  noBanner: {
    backgroundColor: '#1a0f00', borderBottomWidth: 1,
    borderBottomColor: '#3a2000', padding: 20,
  },
  noBannerTitle: {
    color: '#f90', fontSize: 15, fontWeight: '700',
    textAlign: 'center', marginBottom: 6,
  },
  noBannerText: {
    color: '#aaa', fontSize: 13, textAlign: 'center', marginBottom: 16, lineHeight: 18,
  },
  noBannerActions: { flexDirection: 'row', gap: 10, justifyContent: 'center' },
  btnPrimary: {
    backgroundColor: '#4f9eff', borderRadius: 10,
    paddingHorizontal: 18, paddingVertical: 10, flex: 1, alignItems: 'center',
  },
  btnSecondary: {
    backgroundColor: '#2a3a5a', borderRadius: 10,
    paddingHorizontal: 18, paddingVertical: 10, flex: 1, alignItems: 'center',
  },
  btnText: { color: '#fff', fontSize: 13, fontWeight: '600' },
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
