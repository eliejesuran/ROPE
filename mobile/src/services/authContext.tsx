import React, { createContext, useContext, useState, useEffect } from 'react';
import * as SecureStore from 'expo-secure-store';
import { api } from './api';
import { getOrCreateDeviceKeypair } from './crypto';
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
          setUser(parsed);
          // Connecter le socket avec le token existant — pas de nouvel OTP
          try {
            await connectSocket();
            console.log('[Auth] Session restored for userId:', parsed.id);
          } catch (err) {
            console.warn('[Auth] Socket connect failed, will retry on interaction');
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

  const requestOtp = async (phone: string) => {
    const result = await api.auth.requestOtp(phone);
    return { devCode: result.devCode };
  };

  const verifyOtp = async (phone: string, code: string) => {
    const { publicKey } = await getOrCreateDeviceKeypair();
    const result = await api.auth.verifyOtp(phone, code, publicKey);

    // Persister le token et les données utilisateur
    await SecureStore.setItemAsync('auth_token', result.token);
    await SecureStore.setItemAsync('user_data', JSON.stringify(result.user));

    setUser(result.user);
    await connectSocket();
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
