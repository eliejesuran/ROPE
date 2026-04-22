import React, { createContext, useContext, useState, useEffect } from 'react';
import * as SecureStore from 'expo-secure-store';
import { api } from '../services/api';
import { getOrCreateDeviceKeypair } from '../services/crypto';
import { connectSocket, disconnectSocket } from '../services/socket';

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
    // Restore session on app start
    (async () => {
      try {
        const token = await SecureStore.getItemAsync('auth_token');
        const userData = await SecureStore.getItemAsync('user_data');
        if (token && userData) {
          setUser(JSON.parse(userData));
          await connectSocket();
        }
      } catch {
        // Invalid session, clear it
        await SecureStore.deleteItemAsync('auth_token');
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
