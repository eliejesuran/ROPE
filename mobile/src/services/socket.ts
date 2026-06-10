import { io, Socket } from 'socket.io-client';
import * as SecureStore from 'expo-secure-store';
import { AppState } from 'react-native';

const BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:3000';

let socket: Socket | null = null;

// Module-level — added once, not on every connectSocket() call (fixes the listener leak)
AppState.addEventListener('change', (state) => {
  if (state === 'active' && socket && !socket.connected) {
    console.log('[Socket] App active, reconnecting...');
    socket.connect();
  }
});

export async function connectSocket(): Promise<Socket> {
  const token = await SecureStore.getItemAsync('auth_token');
  if (!token) throw new Error('No auth token');

  if (socket?.connected) return socket;

  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
    socket = null;
  }

  socket = io(BASE_URL, {
    auth: { token },
    transports: ['websocket'],
    reconnection: true,
    reconnectionDelay: 2000,
    reconnectionAttempts: Infinity,
    timeout: 10000,
  });

  return new Promise((resolve, reject) => {
    // once — the handler fires at most once then is removed automatically.
    // On connect_error we disconnect immediately so socket.io stops retrying
    // with a token that will never become valid.
    socket!.once('connect', () => {
      console.log('[Socket] Connected:', socket!.id);
      resolve(socket!);
    });

    socket!.once('connect_error', (err) => {
      console.error('[Socket] Connection error:', err.message);
      if (socket) {
        socket.disconnect();
        socket = null;
      }
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
  socket.off('message:new');
  socket.on('message:new', callback);
}

export function offNewMessage() {
  socket?.off('message:new');
}
