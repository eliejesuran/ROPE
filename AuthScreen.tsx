import React, { useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, KeyboardAvoidingView, Platform,
  ActivityIndicator, Alert,
} from 'react-native';
import { useAuth } from '../services/authContext';

type Step = 'phone' | 'otp';

export default function AuthScreen({ onSuccess }: { onSuccess: () => void }) {
  const { requestOtp, verifyOtp } = useAuth();
  const [step, setStep] = useState<Step>('phone');
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [devCode, setDevCode] = useState<string | null>(null);

  const handleRequestOtp = async () => {
    if (!phone.trim()) return;
    setLoading(true);
    try {
      const result = await requestOtp(phone.trim());
      if (result.devCode) {
        setDevCode(result.devCode);
        Alert.alert(
          '🛠 Mode dev',
          `Code OTP : ${result.devCode}\n\n(En production, ce code sera envoyé par SMS)`
        );
      }
      setStep('otp');
    } catch (err: any) {
      Alert.alert('Erreur', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!code.trim()) return;
    setLoading(true);
    try {
      await verifyOtp(phone.trim(), code.trim());
      onSuccess();
    } catch (err: any) {
      Alert.alert('Code invalide', err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      <View style={styles.inner}>
        <Text style={styles.logo}>€uroMsg</Text>
        <Text style={styles.tagline}>Messagerie privée, 100% européenne.</Text>

        {step === 'phone' ? (
          <>
            <Text style={styles.label}>Votre numéro de téléphone</Text>
            <TextInput
              style={styles.input}
              placeholder="+32 471 23 45 67"
              placeholderTextColor="#666"
              keyboardType="phone-pad"
              value={phone}
              onChangeText={setPhone}
              autoFocus
            />
            <TouchableOpacity
              style={[styles.button, loading && styles.buttonDisabled]}
              onPress={handleRequestOtp}
              disabled={loading}
            >
              {loading
                ? <ActivityIndicator color="#fff" />
                : <Text style={styles.buttonText}>Recevoir le code →</Text>
              }
            </TouchableOpacity>
            <Text style={styles.hint}>
              Nous ne stockons jamais votre numéro en clair.{'\n'}
              Conformité RGPD garantie. Hébergé en UE.
            </Text>
          </>
        ) : (
          <>
            <Text style={styles.label}>Code de vérification</Text>
            {devCode && (
              <Text style={styles.devBanner}>
                🛠 DEV — Code : {devCode}
              </Text>
            )}
            <TextInput
              style={[styles.input, styles.otpInput]}
              placeholder="123456"
              placeholderTextColor="#666"
              keyboardType="number-pad"
              maxLength={6}
              value={code}
              onChangeText={setCode}
              autoFocus
            />
            <TouchableOpacity
              style={[styles.button, loading && styles.buttonDisabled]}
              onPress={handleVerifyOtp}
              disabled={loading}
            >
              {loading
                ? <ActivityIndicator color="#fff" />
                : <Text style={styles.buttonText}>Valider</Text>
              }
            </TouchableOpacity>
            <TouchableOpacity onPress={() => { setStep('phone'); setCode(''); }}>
              <Text style={styles.back}>← Changer de numéro</Text>
            </TouchableOpacity>
          </>
        )}
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a0a0f' },
  inner: {
    flex: 1, justifyContent: 'center',
    paddingHorizontal: 32, paddingBottom: 48,
  },
  logo: {
    fontSize: 42, fontWeight: '800',
    color: '#4f9eff', letterSpacing: -1,
    marginBottom: 6,
  },
  tagline: {
    fontSize: 15, color: '#888',
    marginBottom: 48,
  },
  label: {
    fontSize: 13, color: '#aaa',
    marginBottom: 8, fontWeight: '600',
    textTransform: 'uppercase', letterSpacing: 1,
  },
  input: {
    backgroundColor: '#161622',
    borderWidth: 1, borderColor: '#2a2a40',
    borderRadius: 12,
    padding: 16, fontSize: 18,
    color: '#fff', marginBottom: 16,
  },
  otpInput: {
    fontSize: 28, textAlign: 'center',
    letterSpacing: 8,
  },
  button: {
    backgroundColor: '#4f9eff',
    borderRadius: 12, padding: 16,
    alignItems: 'center', marginBottom: 16,
  },
  buttonDisabled: { opacity: 0.5 },
  buttonText: {
    color: '#fff', fontSize: 16,
    fontWeight: '700',
  },
  hint: {
    color: '#555', fontSize: 12,
    textAlign: 'center', lineHeight: 18,
    marginTop: 16,
  },
  back: {
    color: '#4f9eff', textAlign: 'center',
    fontSize: 14, marginTop: 8,
  },
  devBanner: {
    backgroundColor: '#2a1a00',
    borderWidth: 1, borderColor: '#f90',
    borderRadius: 8, padding: 10,
    color: '#f90', fontSize: 13,
    textAlign: 'center', marginBottom: 12,
  },
});
