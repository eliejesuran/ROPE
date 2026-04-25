import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, RefreshControl, TextInput, Alert,
} from 'react-native';
import { api } from '../services/api';
import { useAuth } from '../services/authContext';
import { onNewMessage } from '../services/socket';

interface Conversation {
  conversation_id: string;
  contact_id: string;
  display_name: string | null;
  phone_last4: string;
  public_key: string;
  last_ciphertext: string | null;
  last_message_at: string | null;
}

interface Props {
  onOpenConversation: (conv: Conversation) => void;
}

export default function ConversationListScreen({ onOpenConversation }: Props) {
  const { user, logout } = useAuth();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [searchPhone, setSearchPhone] = useState('');
  const [searching, setSearching] = useState(false);

  const loadConversations = useCallback(async () => {
    try {
      const { conversations } = await api.contacts.conversations();
      setConversations(conversations);
    } catch (err: any) {
      console.error('Failed to load conversations', err.message);
    }
  }, []);

  useEffect(() => {
    loadConversations();
    // Refresh list when a new message arrives
    onNewMessage(() => loadConversations());
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadConversations();
    setRefreshing(false);
  };

  const handleSearch = async () => {
    if (!searchPhone.trim()) return;
    setSearching(true);
    try {
      const result = await api.contacts.find(searchPhone.trim());
      // Add or update conversation
      setConversations(prev => {
        const exists = prev.find(c => c.conversation_id === result.conversationId);
        if (exists) return prev;
        return [{
          conversation_id: result.conversationId,
          contact_id: result.user.id,
          display_name: result.user.displayName,
          phone_last4: result.user.phoneLast4,
          public_key: result.user.publicKey,
          last_ciphertext: null,
          last_message_at: null,
        }, ...prev];
      });
      setSearchPhone('');
    } catch (err: any) {
      Alert.alert('Introuvable', err.message);
    } finally {
      setSearching(false);
    }
  };

  const renderItem = ({ item }: { item: Conversation }) => (
    <TouchableOpacity style={styles.item} onPress={() => onOpenConversation(item)}>
      <View style={styles.avatar}>
        <Text style={styles.avatarText}>
          {(item.display_name || `···${item.phone_last4}`)[0].toUpperCase()}
        </Text>
      </View>
      <View style={styles.itemContent}>
        <Text style={styles.itemName}>
          {item.display_name || `+·······${item.phone_last4}`}
        </Text>
        <Text style={styles.itemPreview} numberOfLines={1}>
          {item.last_ciphertext ? '🔒 Message chiffré' : 'Démarrer la conversation'}
        </Text>
      </View>
      {item.last_message_at && (
        <Text style={styles.itemTime}>
          {new Date(item.last_message_at).toLocaleTimeString('fr-BE', {
            hour: '2-digit', minute: '2-digit',
          })}
        </Text>
      )}
    </TouchableOpacity>
  );

  const handleMenu = () => {
    Alert.alert(
      'Menu',
      null,
      [
        { text: 'Se déconnecter', onPress: logout },
        {
          text: 'Supprimer mon compte',
          style: 'destructive',
          onPress: () => {
            Alert.alert(
              'Supprimer le compte ?',
              'Toutes vos données seront effacées définitivement (RGPD). Cette action est irréversible.',
              [
                { text: 'Annuler', style: 'cancel' },
                {
                  text: 'Supprimer',
                  style: 'destructive',
                  onPress: async () => {
                    try {
                      await api.account.delete();
                      await logout();
                    } catch (err: any) {
                      Alert.alert('Erreur', err.message);
                    }
                  },
                },
              ]
            );
          },
        },
        { text: 'Annuler', style: 'cancel' },
      ]
    );
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>ROPE</Text>
        <TouchableOpacity onPress={handleMenu}>
          <Text style={styles.logoutBtn}>⋯</Text>
        </TouchableOpacity>
      </View>

      {/* Add contact by phone */}
      <View style={styles.searchBar}>
        <TextInput
          style={styles.searchInput}
          placeholder="Ajouter par numéro (+32…)"
          placeholderTextColor="#555"
          keyboardType="phone-pad"
          value={searchPhone}
          onChangeText={setSearchPhone}
          onSubmitEditing={handleSearch}
        />
        <TouchableOpacity
          style={[styles.searchBtn, searching && styles.disabled]}
          onPress={handleSearch}
          disabled={searching}
        >
          <Text style={styles.searchBtnText}>+</Text>
        </TouchableOpacity>
      </View>

      <FlatList
        data={conversations}
        keyExtractor={(item) => item.conversation_id}
        renderItem={renderItem}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} tintColor="#4f9eff" />
        }
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>Aucune conversation.</Text>
            <Text style={styles.emptyHint}>
              Ajoutez un contact en entrant son numéro ci-dessus.
            </Text>
          </View>
        }
      />

      <View style={styles.footer}>
        <Text style={styles.footerText}>
          🔒 End-to-end encrypted · EU-hosted · GDPR
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a0a0f' },
  header: {
    flexDirection: 'row', justifyContent: 'space-between',
    alignItems: 'center', paddingHorizontal: 20,
    paddingTop: 60, paddingBottom: 16,
    borderBottomWidth: 1, borderBottomColor: '#1a1a2e',
  },
  headerTitle: { fontSize: 24, fontWeight: '800', color: '#4f9eff' },
  logoutBtn: { color: '#555', fontSize: 14 },
  searchBar: {
    flexDirection: 'row', gap: 8,
    paddingHorizontal: 16, paddingVertical: 12,
    borderBottomWidth: 1, borderBottomColor: '#1a1a2e',
  },
  searchInput: {
    flex: 1, backgroundColor: '#161622',
    borderRadius: 10, paddingHorizontal: 14,
    paddingVertical: 10, color: '#fff', fontSize: 15,
    borderWidth: 1, borderColor: '#2a2a40',
  },
  searchBtn: {
    backgroundColor: '#4f9eff', borderRadius: 10,
    width: 44, alignItems: 'center', justifyContent: 'center',
  },
  searchBtnText: { color: '#fff', fontSize: 22, fontWeight: '300' },
  disabled: { opacity: 0.4 },
  item: {
    flexDirection: 'row', alignItems: 'center',
    paddingHorizontal: 16, paddingVertical: 14,
    borderBottomWidth: 1, borderBottomColor: '#111120',
  },
  avatar: {
    width: 46, height: 46, borderRadius: 23,
    backgroundColor: '#1a2a4a',
    alignItems: 'center', justifyContent: 'center',
    marginRight: 12,
  },
  avatarText: { color: '#4f9eff', fontSize: 18, fontWeight: '700' },
  itemContent: { flex: 1 },
  itemName: { color: '#fff', fontSize: 16, fontWeight: '600', marginBottom: 3 },
  itemPreview: { color: '#555', fontSize: 13 },
  itemTime: { color: '#444', fontSize: 12 },
  empty: { alignItems: 'center', paddingTop: 80 },
  emptyText: { color: '#666', fontSize: 16, marginBottom: 8 },
  emptyHint: { color: '#444', fontSize: 13, textAlign: 'center', paddingHorizontal: 32 },
  footer: {
    padding: 12, alignItems: 'center',
    borderTopWidth: 1, borderTopColor: '#111120',
  },
  footerText: { color: '#333', fontSize: 11 },
});
