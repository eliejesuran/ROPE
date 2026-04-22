import React, { useState } from 'react';
import { StatusBar } from 'react-native';
import { AuthProvider, useAuth } from './src/services/authContext';
import AuthScreen from './src/screens/AuthScreen';
import ConversationListScreen from './src/screens/ConversationListScreen';
import ChatScreen from './src/screens/ChatScreen';

type Screen = 'auth' | 'conversations' | 'chat';

function AppNavigator() {
  const { user, isLoading } = useAuth();
  const [screen, setScreen] = useState<Screen>('conversations');
  const [activeConversation, setActiveConversation] = useState<any>(null);

  if (isLoading) return null;

  if (!user) {
    return <AuthScreen onSuccess={() => setScreen('conversations')} />;
  }

  if (screen === 'chat' && activeConversation) {
    return (
      <ChatScreen
        conversation={activeConversation}
        onBack={() => { setScreen('conversations'); setActiveConversation(null); }}
      />
    );
  }

  return (
    <ConversationListScreen
      onOpenConversation={(conv) => {
        setActiveConversation(conv);
        setScreen('chat');
      }}
    />
  );
}

export default function App() {
  return (
    <AuthProvider>
      <StatusBar barStyle="light-content" backgroundColor="#0a0a0f" />
      <AppNavigator />
    </AuthProvider>
  );
}
