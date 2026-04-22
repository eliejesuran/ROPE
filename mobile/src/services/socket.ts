import { io, Socket } from 'socket.io-client';
import * as SecureStore from 'expo-secure-store';
import { AppState, AppStateStatus } from 'react-native';

const BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:3000';

let socket: Socket | null = null;

export async function connectSocket(): Promise<Socket> {
  const token = await SecureStore.getItemAsync('auth_token');
  if (!token) throw new Error('No auth token');

  // Si déjà connecté, on garde
  if (socket?.connected) return socket;

  // Si socket existe mais déconnecté, on détruit et recrée
  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
  }

  socket = io(BASE_URL, {
    auth: { token },
    transports: ['websocket'],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: Infinity, // reconnexion infinie
    timeout: 10000,
  });

  // Reconnexion automatique quand l'app revient au premier plan
  AppState.addEventListener('change', async (state: AppStateStatus) => {
    if (state === 'active' && socket && !socket.connected) {
      console.log('[Socket] App active, reconnecting...');
      socket.connect();
    }
  });

  return new Promise((resolve, reject) => {
    socket!.on('connect', () => {
      console.log('[Socket] Connected:', socket!.id);
      resolve(socket!);
    });
    socket!.on('connect_error', (err) => {
      console.error('[Socket] Connection error:', err.message);
      reject(err);
    });
  });
}

export function getSocket(): Socket | null {
  return socket;
}

export function disconnectSocket() {
  socket?.removeAllListeners();
  socket?.disconnect();
  socket = null;
}

export function onNewMessage(callback: (msg: any) => void) {
  if (!socket) return;
  socket.off('message:new'); // évite les doublons
  socket.on('message:new', callback);
}

export function offNewMessage() {
  socket?.off('message:new');
}
