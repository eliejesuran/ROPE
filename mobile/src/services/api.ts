import * as SecureStore from 'expo-secure-store';

const BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:3000';

async function getToken(): Promise<string | null> {
  return SecureStore.getItemAsync('auth_token');
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = await getToken();

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const api = {
  auth: {
    requestOtp: (phone: string) =>
      request<{ success: boolean; devCode?: string }>('/api/auth/request-otp', {
        method: 'POST',
        body: JSON.stringify({ phone }),
      }),

    verifyOtp: (phone: string, code: string, publicKey: string) =>
      request<{ token: string; user: { id: string; displayName: string; phoneLast4: string } }>(
        '/api/auth/verify-otp',
        { method: 'POST', body: JSON.stringify({ phone, code, publicKey }) }
      ),
  },

  contacts: {
    find: (phone: string) =>
      request<{
        user: { id: string; displayName: string; phoneLast4: string; publicKey: string };
        conversationId: string;
      }>('/api/contacts/find', { method: 'POST', body: JSON.stringify({ phone }) }),

    conversations: () =>
      request<{ conversations: any[] }>('/api/contacts/conversations'),
  },

  messages: {
    get: (conversationId: string, before?: string) =>
      request<{ messages: any[] }>(
        `/api/messages/${conversationId}${before ? `?before=${before}` : ''}`
      ),

    send: (conversationId: string, ciphertext: string, iv: string) =>
      request<{ id: string; sentAt: string }>('/api/messages', {
        method: 'POST',
        body: JSON.stringify({ conversationId, ciphertext, iv }),
      }),
  },

  account: {
    delete: () => request('/api/account', { method: 'DELETE' }),
    updateDisplayName: (displayName: string) =>
      request('/api/account/display-name', {
        method: 'PATCH',
        body: JSON.stringify({ displayName }),
      }),
  },
};
