import React, { createContext, useContext, useState, useEffect } from 'react';
import * as SecureStore from 'expo-secure-store';
import { api } from './api';
import {
  getOrCreateDeviceKeypair,
  getOrCreateSignedPreKey,
  generateOneTimePreKeys,
} from './crypto';
import { connectSocket, disconnectSocket } from './socket';

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
    // Generate OPKs only once per device — the flag prevents re-upload on every login
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

    // Upload X3DH key bundle — best-effort, OPKs generated once per device
    uploadKeyBundle(publicKey).catch((err) => {
      console.warn('[Auth] Key bundle upload failed:', err.message);
    });
  };

  const logout = async () => {
    disconnectSocket();
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
