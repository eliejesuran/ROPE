import React, { createContext, useContext, useState, useEffect } from 'react';
import * as SecureStore from 'expo-secure-store';
import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';
import { api } from './api';
import {
  getOrCreateDeviceKeypair,
  getOrCreateSignedPreKey,
  rotateSignedPreKey,
  generateOneTimePreKeys,
} from './crypto';
import { connectSocket, disconnectSocket } from './socket';

const SPK_MAX_AGE_DAYS = 7;

interface User {
  id: string;
  displayName: string | null;
  phoneLast4: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  requestOtp: (phone: string) => Promise<{ devCode?: string }>;
  verifyOtp: (phone: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Restaurer la session existante au démarrage
    (async () => {
      try {
        const token = await SecureStore.getItemAsync('auth_token');
        const userData = await SecureStore.getItemAsync('user_data');

        if (token && userData) {
          const parsed = JSON.parse(userData);
          try {
            await connectSocket();
            // Socket OK — restore session
            setUser(parsed);
            console.log('[Auth] Session restored for userId:', parsed.id);
          } catch (err: any) {
            const isAuthError = err?.message === 'Invalid token' || err?.message === 'Authentication required';
            if (isAuthError) {
              // Server rejected the token — clear everything, go to login
              console.warn('[Auth] Token rejected by server, clearing session');
              await SecureStore.deleteItemAsync('auth_token');
              await SecureStore.deleteItemAsync('user_data');
            } else {
              // Network error — keep session, REST calls will still work
              setUser(parsed);
              console.warn('[Auth] Socket unavailable, continuing without real-time');
            }
          }
        }
      } catch (err) {
        console.warn('[Auth] Failed to restore session:', err);
        await SecureStore.deleteItemAsync('auth_token');
        await SecureStore.deleteItemAsync('user_data');
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  async function uploadKeyBundle(ikPub: string) {
    const spk  = await getOrCreateSignedPreKey();
    const uploaded = await SecureStore.getItemAsync('opks_uploaded');
    const opks = uploaded ? [] : await generateOneTimePreKeys(10);
    await api.keys.uploadBundle({
      ikPub,
      ikSigningPub:  spk.ikSigningPub,
      spkPub:        spk.spkPub,
      spkSig:        spk.spkSig,
      spkId:         spk.spkId,
      oneTimePreKeys: opks,
    });
    if (!uploaded) await SecureStore.setItemAsync('opks_uploaded', 'true');
  }

  async function checkAndRotateKeys(ikPub: string) {
    try {
      const status = await api.keys.getStatus();

      // Replenish OPKs if running low
      if (status.opkCount < 5) {
        const newOpks = await generateOneTimePreKeys(10);
        const spk = await getOrCreateSignedPreKey();
        await api.keys.uploadBundle({
          ikPub,
          ikSigningPub: spk.ikSigningPub,
          spkPub: spk.spkPub,
          spkSig: spk.spkSig,
          spkId: spk.spkId,
          oneTimePreKeys: newOpks,
        });
      }

      // Rotate SPK if older than SPK_MAX_AGE_DAYS
      if (status.spkCreatedAt) {
        const ageDays = (Date.now() - new Date(status.spkCreatedAt).getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays >= SPK_MAX_AGE_DAYS) {
          const newSpk = await rotateSignedPreKey();
          await api.keys.uploadBundle({
            ikPub,
            ikSigningPub: newSpk.ikSigningPub,
            spkPub: newSpk.spkPub,
            spkSig: newSpk.spkSig,
            spkId: newSpk.spkId,
            oneTimePreKeys: [],
          });
        }
      }
    } catch (err: any) {
      console.warn('[Keys] Key rotation check failed:', err.message);
    }
  }

  async function registerPushToken() {
    try {
      const { status: existing } = await Notifications.getPermissionsAsync();
      let finalStatus = existing;
      if (existing !== 'granted') {
        const { status } = await Notifications.requestPermissionsAsync();
        finalStatus = status;
      }
      if (finalStatus !== 'granted') return;

      const { data: token } = await Notifications.getExpoPushTokenAsync();
      const platform = Platform.OS === 'ios' ? 'ios' : 'android';
      await api.push.register(token, platform);
      await SecureStore.setItemAsync('push_token', token);
    } catch (err: any) {
      console.warn('[Push] Token registration failed:', err.message);
    }
  }

  const requestOtp = async (phone: string) => {
    const result = await api.auth.requestOtp(phone);
    return { devCode: result.devCode };
  };

  const verifyOtp = async (phone: string, code: string) => {
    const { publicKey } = await getOrCreateDeviceKeypair();
    const result = await api.auth.verifyOtp(phone, code, publicKey);

    await SecureStore.setItemAsync('auth_token', result.token);
    await SecureStore.setItemAsync('user_data', JSON.stringify(result.user));
    setUser(result.user);

    connectSocket().catch((err) => {
      console.warn('[Auth] Socket connect failed after login:', err.message);
    });

    // Upload key bundle then check rotation + push in background
    uploadKeyBundle(publicKey)
      .then(() => checkAndRotateKeys(publicKey))
      .catch((err) => console.warn('[Auth] Key bundle upload failed:', err.message));

    registerPushToken();
  };

  const logout = async () => {
    disconnectSocket();
    const pushToken = await SecureStore.getItemAsync('push_token');
    if (pushToken) {
      api.push.unregister(pushToken).catch(() => {});
      await SecureStore.deleteItemAsync('push_token');
    }
    await SecureStore.deleteItemAsync('auth_token');
    await SecureStore.deleteItemAsync('user_data');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, requestOtp, verifyOtp, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
