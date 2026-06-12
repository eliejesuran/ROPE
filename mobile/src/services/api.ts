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

    send: (conversationId: string, ciphertext: string, iv: string, ratchetHeader?: string, expiresIn?: number | null) =>
      request<{ id: string; sentAt: string; expiresAt: string | null }>('/api/messages', {
        method: 'POST',
        body: JSON.stringify({ conversationId, ciphertext, iv, ratchetHeader, expiresIn: expiresIn ?? undefined }),
      }),
  },

  account: {
    delete: () => request('/api/account', { method: 'DELETE' }),
    export: () => request<{
      exportedAt: string;
      user: { id: string; phoneLast4: string; displayName: string | null; createdAt: string };
      conversations: Array<{ id: string; contactLast4: string; contactDisplayName: string | null; startedAt: string; messageCount: number }>;
      note: string;
    }>('/api/account/export'),
    updateDisplayName: (displayName: string) =>
      request('/api/account/display-name', {
        method: 'PATCH',
        body: JSON.stringify({ displayName }),
      }),
  },

  keys: {
    uploadBundle: (bundle: {
      ikPub: string; ikSigningPub: string;
      spkPub: string; spkSig: string; spkId: number;
      oneTimePreKeys: Array<{ id: number; pub: string }>;
    }) => request('/api/keys/bundle', { method: 'PUT', body: JSON.stringify(bundle) }),

    getBundle: (userId: string) =>
      request<{
        userId: string; ikPub: string; ikSigningPub: string;
        spkPub: string; spkSig: string; spkId: number;
        opk: { id: number; pub: string } | null;
      }>(`/api/keys/bundle/${userId}`),

    postX3DHInit: (conversationId: string, data: { ikPub: string; ekPub: string; opkId: number | null; spkId?: number | null }) =>
      request('/api/keys/x3dh-init', {
        method: 'POST',
        body: JSON.stringify({ conversationId, ...data }),
      }),

    getX3DHInit: (conversationId: string) =>
      request<{ initiatorId: string; ikPub: string; ekPub: string; opkId: number | null; spkId: number | null }>(
        `/api/keys/x3dh-init/${conversationId}`
      ),

    deleteX3DHInit: (conversationId: string) =>
      request(`/api/keys/x3dh-init/${conversationId}`, { method: 'DELETE' }),

    getStatus: () =>
      request<{ opkCount: number; spkId: number | null; spkCreatedAt: string | null }>(
        '/api/keys/status'
      ),
  },

  push: {
    register: (token: string, platform: 'ios' | 'android') =>
      request('/api/push/register', {
        method: 'POST',
        body: JSON.stringify({ token, platform }),
      }),
    unregister: (token: string) =>
      request('/api/push/unregister', {
        method: 'DELETE',
        body: JSON.stringify({ token }),
      }),
  },
};
