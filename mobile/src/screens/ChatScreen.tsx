import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View, Text, FlatList, TextInput, TouchableOpacity,
  StyleSheet, KeyboardAvoidingView, Platform, Alert,
  ActivityIndicator, AppState,
} from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { api } from '../services/api';
import { useAuth } from '../services/authContext';
import {
  decryptMessage,
  getConversationKey,
  x3dhInitiator, x3dhResponder,
  hasDRState, drCanSend, drEncrypt, drDecrypt,
  getKnownPeerIk, setKnownPeerIk, wipeConversationCrypto,
  type DRHeader,
} from '../services/crypto';
import { getPlaintext, setPlaintext } from '../services/messageStore';
import { onNewMessage, offNewMessage, onReconnect, offReconnect, getSocket } from '../services/socket';

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
  const [hasMore, setHasMore] = useState(true);    // older pages left to fetch
  const [tick, setTick] = useState(0);             // re-render driver for 🔥 countdowns
  const [identityChanged, setIdentityChanged] = useState(false); // reset-protocol banner
  const flatListRef = useRef<FlatList>(null);
  const loadingOlder = useRef(false);
  const suppressAutoScroll = useRef(false);        // pagination prepend must not yank to bottom
  const identityRecheckDone = useRef(false);       // one identity re-check per mount
  const identityRecheckRef = useRef<(() => void) | null>(null);
  const convId = conversation.conversation_id;

  // Resolve one message to plaintext.
  // DR keys are single-use (forward secrecy): a message decrypts exactly ONCE,
  // then its plaintext lives in the local store. Order matters:
  //   1. local store hit  → done (covers everything already seen + own sends)
  //   2. own message miss → undecryptable by design (sending-chain key), placeholder
  //   3. never-seen incoming message → decrypt once, persist plaintext
  const decrypt = useCallback(async (msg: Message): Promise<Message> => {
    const cached = await getPlaintext(convId, msg.id);
    if (cached !== null) return { ...msg, plaintext: cached };

    if (msg.sender_id === user!.id) {
      return { ...msg, plaintext: '[Envoyé depuis un autre appareil]', error: true };
    }

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
      await setPlaintext(convId, msg.id, plaintext, msg.expires_at);
      return { ...msg, plaintext };
    } catch {
      // Lost a race: a concurrent path (socket vs catch-up fetch) may have
      // decrypted this exact message while we waited on the ratchet lock —
      // its single-use key is consumed but the plaintext is already cached.
      const late = await getPlaintext(convId, msg.id);
      if (late !== null) return { ...msg, plaintext: late };
      // A fresh message we can't decrypt can mean the peer reinstalled the
      // app (new identity, new ratchet) — trigger one identity re-check.
      identityRecheckRef.current?.();
      return { ...msg, plaintext: '[Clé incorrecte ou manquante]', error: true };
    }
  }, [convId, user]);

  // Coalesced: reconnect + foreground can both request a reload at once —
  // a single in-flight pass serves both callers.
  const loadInFlight = useRef<Promise<void> | null>(null);

  const loadMessages = useCallback(() => {
    if (loadInFlight.current) return loadInFlight.current;
    loadInFlight.current = (async () => {
      try {
        const { messages: raw } = await api.messages.get(convId);
        if (raw.length < 50) setHasMore(false);
        const decrypted: Message[] = [];
        for (const msg of raw) {
          decrypted.push(await decrypt(msg));
        }
        // Merge: keep what isn't in this page — live socket arrivals AND older
        // paginated messages — then restore chronological order
        setMessages(prev => {
          const loaded = new Set(decrypted.map(m => m.id));
          const merged = [...decrypted, ...prev.filter(m => !loaded.has(m.id))]
            .sort((x, y) => new Date(x.sent_at).getTime() - new Date(y.sent_at).getTime());
          // Polled reload: skip the re-render when nothing actually changed
          const unchanged = merged.length === prev.length
            && merged.every((m, i) => m.id === prev[i].id && m.plaintext === prev[i].plaintext);
          return unchanged ? prev : merged;
        });
      } catch (err: any) {
        console.error('Failed to load messages', err.message);
      } finally {
        setLoading(false);
        loadInFlight.current = null;
      }
    })();
    return loadInFlight.current;
  }, [convId, decrypt]);

  // Pagination: fetch the previous page when the user scrolls to the top
  const loadOlder = useCallback(async () => {
    if (loadingOlder.current || !hasMore || messages.length === 0) return;
    loadingOlder.current = true;
    try {
      const { messages: raw } = await api.messages.get(convId, messages[0].sent_at);
      if (raw.length < 50) setHasMore(false);
      if (raw.length === 0) return;
      const older: Message[] = [];
      for (const msg of raw) {
        older.push(await decrypt(msg));
      }
      suppressAutoScroll.current = true;
      setMessages(prev => {
        const have = new Set(prev.map(m => m.id));
        return [...older.filter(o => !have.has(o.id)), ...prev];
      });
    } catch (err: any) {
      console.error('Failed to load older messages', err.message);
    } finally {
      loadingOlder.current = false;
    }
  }, [convId, decrypt, hasMore, messages]);

  // ── Session establishment (X3DH + DR) — includes the reset protocol ───────
  const establishSession = useCallback(async () => {
    // Identity check: if the contact's IK changed (reinstall / new device),
    // our ratchet can never re-synchronise — tear it down and re-handshake.
    // The decrypted history (messageStore) is kept.
    try {
      const { ikPub: peerIk } = await api.keys.getIdentity(conversation.contact_id);
      const known = await getKnownPeerIk(convId);
      if (known && known !== peerIk) {
        console.warn('[X3DH] Peer identity changed — resetting session');
        await wipeConversationCrypto(convId);
        setIdentityChanged(true);
      } else if (!known && (await hasDRState(convId))) {
        // Session predates identity pinning — trust on first use
        await setKnownPeerIk(convId, peerIk);
      }
    } catch { /* offline or contact has no bundle yet — keep local state */ }

    // Usable session = conversation key + Double Ratchet state
    if ((await getConversationKey(convId)) && (await hasDRState(convId))) {
      setDrReady(await drCanSend(convId));
      setKeyStatus('ready');
      return;
    }

    // No usable session — establish one via X3DH
    setKeyStatus('establishing');
    try {
      let initData:
        { initiatorId: string; ikPub: string; ekPub: string; opkId: number | null; spkId: number | null } | null = null;
      try { initData = await api.keys.getX3DHInit(convId); } catch { /* no init yet */ }

      if (initData) {
        // Become responder: the other party already posted the X3DH init
        await x3dhResponder(convId, initData);
      } else {
        // Become initiator: fetch contact's bundle and post the X3DH init
        const bundle   = await api.keys.getBundle(conversation.contact_id);
        const myIkPub  = (await SecureStore.getItemAsync('ik_pub'))!;
        const { ekPub, opkId, spkId } = await x3dhInitiator(convId, bundle);

        try {
          await api.keys.postX3DHInit(convId, { ikPub: myIkPub, ekPub, opkId, spkId });
        } catch (err: any) {
          if (err.message === 'X3DH init already exists') {
            try {
              // Race: the other party posted first — become responder
              const lateInit = await api.keys.getX3DHInit(convId);
              await x3dhResponder(convId, lateInit);
            } catch (e: any) {
              if (e.message === 'No X3DH init found') {
                // WE are the recorded initiator but lost the local session
                // (reinstall): the stored init is unrecoverable for everyone.
                // Invalidate it and post our fresh one instead.
                await api.keys.deleteX3DHInit(convId);
                await api.keys.postX3DHInit(convId, { ikPub: myIkPub, ekPub, opkId, spkId });
              } else {
                throw e;
              }
            }
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
  }, [convId, conversation.contact_id]);

  useEffect(() => {
    identityRecheckDone.current = false;
    // A fresh message we couldn't decrypt while the conversation is open can
    // mean the peer reinstalled — one re-check per mount: if the identity
    // really changed, reset, re-handshake and catch up (the failed message
    // becomes decryptable: it sits at the start of the new sending chain).
    identityRecheckRef.current = () => {
      if (identityRecheckDone.current) return;
      identityRecheckDone.current = true;
      (async () => {
        try {
          const { ikPub: peerIk } = await api.keys.getIdentity(conversation.contact_id);
          const known = await getKnownPeerIk(convId);
          if (known && known !== peerIk) {
            await establishSession();   // detects the mismatch → wipe + re-handshake
            await loadMessages();
          }
        } catch { /* offline — ignore */ }
      })();
    };

    (async () => {
      await establishSession();
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
      // Dedup: the same message can also come back via loadMessages
      setMessages(prev => prev.some(m => m.id === decrypted.id) ? prev : [...prev, decrypted]);
      getSocket()?.emit('message:read', { messageId: msg.id, conversationId: convId });
    });

    // Catch-up: iOS drops the socket in background, and push doesn't reach
    // Expo Go — messages sent meanwhile only exist on the server. Refetch on
    // reconnect/foreground + a light poll while the conversation is open;
    // the local store makes each pass cheap and idempotent (cache hits).
    onReconnect(() => { loadMessages(); });
    const appStateSub = AppState.addEventListener('change', (state) => {
      if (state === 'active') loadMessages();
    });
    const pollId = setInterval(() => loadMessages(), 8000);
    // 🔥 countdowns are computed at render time — tick to refresh them
    const tickId = setInterval(() => setTick(t => t + 1), 30000);

    return () => {
      offNewMessage();
      offReconnect();
      appStateSub.remove();
      clearInterval(pollId);
      clearInterval(tickId);
    };
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
      // Own messages can never be re-decrypted (sending-chain key) — persist now
      setPlaintext(convId, id, text, expiresAt).catch(() => {});
      setMessages(prev => [...prev, {
        id, sender_id: user!.id,
        ciphertext, iv, ratchet_header: ratchetHeader, sent_at: sentAt,
        expires_at: expiresAt, plaintext: text,
      }]);
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
      {identityChanged && (
        <View style={[styles.statusBanner, styles.statusBannerWarn]}>
          <Text style={styles.statusText}>
            🔑 L'identité de votre contact a changé (réinstallation ou nouvel appareil).
            Le chiffrement a été ré-établi avec ses nouvelles clés.
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
            extraData={tick}
            keyExtractor={(item) => item.id}
            renderItem={renderMessage}
            contentContainerStyle={styles.messageList}
            onLayout={() => flatListRef.current?.scrollToEnd({ animated: false })}
            onContentSizeChange={() => {
              // Pagination prepends above the viewport — don't yank to bottom
              if (suppressAutoScroll.current) { suppressAutoScroll.current = false; return; }
              flatListRef.current?.scrollToEnd({ animated: true });
            }}
            onStartReached={loadOlder}
            onStartReachedThreshold={0.1}
            maintainVisibleContentPosition={{ minIndexForVisible: 0 }}
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
          <Text style={[styles.ttlText, TTL_OPTIONS[ttlIndex].value !== null && styles.ttlActive]}>
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
  statusBannerWarn: { backgroundColor: '#1a1505', borderBottomColor: '#3a3000' },
  statusText: { color: '#aaa', fontSize: 12, textAlign: 'center', lineHeight: 17 },
  messageList: { padding: 16, paddingBottom: 8 },
  bubble: { maxWidth: '78%', borderRadius: 16, padding: 10, marginBottom: 8 },
  bubbleMine: { alignSelf: 'flex-start', backgroundColor: '#1a3a6a', borderBottomLeftRadius: 4 },
  bubbleTheirs: { alignSelf: 'flex-end', backgroundColor: '#1a1a2e', borderBottomRightRadius: 4 },
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
