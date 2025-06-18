import React, { useState, useEffect, createContext, useContext } from 'react';
import axios from 'axios';
import './App.css';

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Crypto utilities for client-side encryption
const CryptoUtils = {
  // Generate encryption key from master password
  async generateKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      encoder.encode(masterPassword),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: encoder.encode(salt),
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  // Encrypt password
  async encryptPassword(password, masterPassword, userEmail) {
    try {
      const key = await this.generateKey(masterPassword, userEmail);
      const encoder = new TextEncoder();
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(password)
      );
      
      // Combine IV and encrypted data
      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encrypted), iv.length);
      
      return btoa(String.fromCharCode(...combined));
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Failed to encrypt password');
    }
  },

  // Decrypt password
  async decryptPassword(encryptedPassword, masterPassword, userEmail) {
    try {
      const key = await this.generateKey(masterPassword, userEmail);
      const combined = new Uint8Array(atob(encryptedPassword).split('').map(c => c.charCodeAt(0)));
      
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);
      
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
      );
      
      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt password');
    }
  }
};

// API Configuration
const API_BASE_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth Provider Component
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [masterPasswordVerified, setMasterPasswordVerified] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    const userData = localStorage.getItem('user_data');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const response = await api.post('/api/auth/login', { email, password });
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('auth_token', access_token);
      localStorage.setItem('user_data', JSON.stringify(userData));
      setUser(userData);
      
      return userData;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Login failed');
    }
  };

  const register = async (email, password, fullName) => {
    try {
      const response = await api.post('/api/auth/register', {
        email,
        password,
        full_name: fullName
      });
      const { access_token, user: userData } = response.data;
      
      localStorage.setItem('auth_token', access_token);
      localStorage.setItem('user_data', JSON.stringify(userData));
      setUser(userData);
      
      return userData;
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Registration failed');
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
    localStorage.removeItem('master_password');
    setUser(null);
    setMasterPasswordVerified(false);
  };

  const value = {
    user,
    loading,
    masterPasswordVerified,
    setMasterPasswordVerified,
    login,
    register,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Login Component
const LoginForm = ({ onSwitchToRegister }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await login(email, password);
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
        <div className="text-center mb-8">
          <div className="text-4xl mb-4">🔐</div>
          <h1 className="text-3xl font-bold text-white mb-2">Secure Vault</h1>
          <p className="text-blue-200">Your passwords, safely encrypted</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-white mb-2 font-medium">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="Enter your email"
              required
            />
          </div>

          <div>
            <label className="block text-white mb-2 font-medium">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="Enter your password"
              required
            />
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed hover:from-blue-700 hover:to-purple-700 transition-all duration-200"
          >
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>

        <div className="text-center mt-6">
          <p className="text-blue-200">
            Don't have an account?{' '}
            <button
              onClick={onSwitchToRegister}
              className="text-blue-300 hover:text-blue-100 font-semibold underline"
            >
              Create Account
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Register Component
const RegisterForm = ({ onSwitchToLogin }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await register(email, password, fullName);
    } catch (error) {
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
        <div className="text-center mb-8">
          <div className="text-4xl mb-4">🔐</div>
          <h1 className="text-3xl font-bold text-white mb-2">Create Account</h1>
          <p className="text-blue-200">Join Secure Vault today</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-white mb-2 font-medium">Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="Enter your full name"
              required
            />
          </div>

          <div>
            <label className="block text-white mb-2 font-medium">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="Enter your email"
              required
            />
          </div>

          <div>
            <label className="block text-white mb-2 font-medium">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder="Create a strong password"
              required
              minLength={6}
            />
          </div>

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed hover:from-blue-700 hover:to-purple-700 transition-all duration-200"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        <div className="text-center mt-6">
          <p className="text-blue-200">
            Already have an account?{' '}
            <button
              onClick={onSwitchToLogin}
              className="text-blue-300 hover:text-blue-100 font-semibold underline"
            >
              Sign In
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

// Master Password Component
const MasterPasswordSetup = () => {
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { user, setMasterPasswordVerified } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (masterPassword !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (masterPassword.length < 8) {
      setError('Master password must be at least 8 characters long');
      setLoading(false);
      return;
    }

    try {
      if (!user.master_password_set) {
        await api.post('/api/auth/set-master-password', {
          master_password: masterPassword
        });
      }
      
      // Store master password temporarily for encryption/decryption
      localStorage.setItem('master_password', masterPassword);
      setMasterPasswordVerified(true);
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to set master password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 w-full max-w-md border border-white/20">
        <div className="text-center mb-8">
          <div className="text-4xl mb-4">🔑</div>
          <h1 className="text-3xl font-bold text-white mb-2">Master Password</h1>
          <p className="text-blue-200">
            {user?.master_password_set 
              ? 'Enter your master password to access your vault'
              : 'Set a master password to encrypt your passwords'
            }
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-white mb-2 font-medium">Master Password</label>
            <input
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
              placeholder={user?.master_password_set ? 'Enter master password' : 'Create master password'}
              required
              minLength={8}
            />
            <p className="text-blue-300 text-sm mt-1">
              This password encrypts all your stored passwords
            </p>
          </div>

          {!user?.master_password_set && (
            <div>
              <label className="block text-white mb-2 font-medium">Confirm Master Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-lg bg-white/20 border border-white/30 text-white placeholder-white/60 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
                placeholder="Confirm master password"
                required
                minLength={8}
              />
            </div>
          )}

          {error && (
            <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed hover:from-blue-700 hover:to-purple-700 transition-all duration-200"
          >
            {loading ? 'Processing...' : (user?.master_password_set ? 'Unlock Vault' : 'Set Master Password')}
          </button>
        </form>

        <div className="mt-6 text-center">
          <div className="bg-yellow-500/20 border border-yellow-500/50 text-yellow-200 px-4 py-3 rounded-lg text-sm">
            ⚠️ Remember this password! It cannot be recovered if lost.
          </div>
        </div>
      </div>
    </div>
  );
};

// Password Manager Dashboard
const PasswordManager = () => {
  const [passwords, setPasswords] = useState([]);
  const [folders, setFolders] = useState([]);
  const [selectedFolder, setSelectedFolder] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [showAddFolder, setShowAddFolder] = useState(false);
  const [loading, setLoading] = useState(true);
  const [masterPassword, setMasterPassword] = useState('');
  const { user, logout } = useAuth();

  useEffect(() => {
    const storedMasterPassword = localStorage.getItem('master_password');
    if (storedMasterPassword) {
      setMasterPassword(storedMasterPassword);
    }
    loadData();
  }, [selectedFolder, searchTerm]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [passwordsRes, foldersRes] = await Promise.all([
        api.get('/api/passwords', {
          params: {
            folder_id: selectedFolder,
            search: searchTerm || undefined
          }
        }),
        api.get('/api/folders')
      ]);
      
      setPasswords(passwordsRes.data.passwords || []);
      setFolders(foldersRes.data.folders || []);
    } catch (error) {
      console.error('Error loading data:', error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      // You could add a toast notification here
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const decryptPassword = async (encryptedPassword) => {
    try {
      return await CryptoUtils.decryptPassword(encryptedPassword, masterPassword, user.email);
    } catch (error) {
      console.error('Decryption failed:', error);
      return 'Failed to decrypt';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <div className="text-2xl">🔐</div>
              <h1 className="text-xl font-semibold text-gray-900">Secure Vault</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <span className="text-gray-600">Welcome, {user?.full_name}</span>
              <button
                onClick={logout}
                className="text-gray-500 hover:text-gray-700 font-medium"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-8">
          {/* Sidebar */}
          <div className="w-64 flex-shrink-0">
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Actions</h3>
                  <div className="space-y-2">
                    <button
                      onClick={() => setShowAddForm(true)}
                      className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      Add Password
                    </button>
                    <button
                      onClick={() => setShowAddFolder(true)}
                      className="w-full bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors"
                    >
                      Add Folder
                    </button>
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Folders</h3>
                  <div className="space-y-1">
                    <button
                      onClick={() => setSelectedFolder(null)}
                      className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                        selectedFolder === null ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
                      }`}
                    >
                      📁 All Passwords
                    </button>
                    {folders.map((folder) => (
                      <button
                        key={folder.folder_id}
                        onClick={() => setSelectedFolder(folder.folder_id)}
                        className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                          selectedFolder === folder.folder_id ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        <span style={{ color: folder.color }}>📁</span> {folder.name}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1">
            {/* Search Bar */}
            <div className="mb-6">
              <input
                type="text"
                placeholder="Search passwords..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>

            {/* Password List */}
            <div className="bg-white rounded-lg shadow-sm">
              {loading ? (
                <div className="p-8 text-center text-gray-500">Loading passwords...</div>
              ) : passwords.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  No passwords found. {searchTerm ? 'Try a different search term.' : 'Add your first password!'}
                </div>
              ) : (
                <div className="divide-y divide-gray-200">
                  {passwords.map((password) => (
                    <PasswordItem
                      key={password.password_id}
                      password={password}
                      onCopy={copyToClipboard}
                      onDecrypt={decryptPassword}
                      onRefresh={loadData}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      {showAddForm && (
        <AddPasswordModal
          folders={folders}
          onClose={() => setShowAddForm(false)}
          onSuccess={() => {
            setShowAddForm(false);
            loadData();
          }}
          masterPassword={masterPassword}
          userEmail={user.email}
        />
      )}

      {showAddFolder && (
        <AddFolderModal
          onClose={() => setShowAddFolder(false)}
          onSuccess={() => {
            setShowAddFolder(false);
            loadData();
          }}
        />
      )}
    </div>
  );
};

// Password Item Component
const PasswordItem = ({ password, onCopy, onDecrypt, onRefresh }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [decryptedPassword, setDecryptedPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleShowPassword = async () => {
    if (!showPassword && !decryptedPassword) {
      setLoading(true);
      try {
        const decrypted = await onDecrypt(password.encrypted_password);
        setDecryptedPassword(decrypted);
      } catch (error) {
        console.error('Decryption failed:', error);
      } finally {
        setLoading(false);
      }
    }
    setShowPassword(!showPassword);
  };

  const handleCopyPassword = async () => {
    if (!decryptedPassword) {
      setLoading(true);
      try {
        const decrypted = await onDecrypt(password.encrypted_password);
        setDecryptedPassword(decrypted);
        await onCopy(decrypted);
      } catch (error) {
        console.error('Failed to copy password:', error);
      } finally {
        setLoading(false);
      }
    } else {
      await onCopy(decryptedPassword);
    }
  };

  return (
    <div className="p-6 hover:bg-gray-50 transition-colors">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="flex items-center space-x-3 mb-2">
            <h3 className="text-lg font-semibold text-gray-900">{password.title}</h3>
            {password.website_url && (
              <a
                href={password.website_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-800 text-sm"
              >
                🔗 Visit
              </a>
            )}
          </div>
          
          <div className="space-y-1">
            <p className="text-sm text-gray-600">
              <span className="font-medium">Username:</span> {password.username}
            </p>
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-600 font-medium">Password:</span>
              <span className="text-sm font-mono">
                {showPassword ? (loading ? 'Decrypting...' : decryptedPassword || '••••••••') : '••••••••'}
              </span>
              <button
                onClick={handleShowPassword}
                disabled={loading}
                className="text-blue-600 hover:text-blue-800 text-sm disabled:opacity-50"
              >
                {showPassword ? '🙈 Hide' : '👁️ Show'}
              </button>
              <button
                onClick={handleCopyPassword}
                disabled={loading}
                className="text-green-600 hover:text-green-800 text-sm disabled:opacity-50"
              >
                📋 Copy
              </button>
            </div>
            {password.notes && (
              <p className="text-sm text-gray-600">
                <span className="font-medium">Notes:</span> {password.notes}
              </p>
            )}
          </div>
        </div>

        <div className="ml-4 flex items-center space-x-2">
          <button
            onClick={() => {/* Edit functionality */}}
            className="text-gray-400 hover:text-gray-600"
          >
            ✏️
          </button>
          <button
            onClick={() => {/* Delete functionality */}}
            className="text-red-400 hover:text-red-600"
          >
            🗑️
          </button>
        </div>
      </div>
    </div>
  );
};

// Add Password Modal
const AddPasswordModal = ({ folders, onClose, onSuccess, masterPassword, userEmail }) => {
  const [formData, setFormData] = useState({
    title: '',
    website_url: '',
    username: '',
    password: '',
    notes: '',
    folder_id: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Encrypt password on client side
      const encryptedPassword = await CryptoUtils.encryptPassword(
        formData.password,
        masterPassword,
        userEmail
      );

      await api.post('/api/passwords', {
        ...formData,
        encrypted_password: encryptedPassword,
        folder_id: formData.folder_id || null
      });

      onSuccess();
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to add password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold mb-4">Add New Password</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) => setFormData({...formData, title: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="e.g., Gmail, Facebook"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Website URL</label>
            <input
              type="url"
              value={formData.website_url}
              onChange={(e) => setFormData({...formData, website_url: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="https://example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({...formData, username: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter username or email"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Enter password"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Folder</label>
            <select
              value={formData.folder_id}
              onChange={(e) => setFormData({...formData, folder_id: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">No Folder</option>
              {folders.map((folder) => (
                <option key={folder.folder_id} value={folder.folder_id}>
                  {folder.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Notes</label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({...formData, notes: e.target.value})}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              rows="3"
              placeholder="Optional notes"
            />
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Adding...' : 'Add Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Add Folder Modal
const AddFolderModal = ({ onClose, onSuccess }) => {
  const [name, setName] = useState('');
  const [color, setColor] = useState('#3B82F6');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const colors = [
    '#3B82F6', '#EF4444', '#10B981', '#F59E0B',
    '#8B5CF6', '#EC4899', '#6B7280', '#14B8A6'
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await api.post('/api/folders', { name, color });
      onSuccess();
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to create folder');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold mb-4">Create New Folder</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Folder Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="e.g., Work, Personal, Social"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Color</label>
            <div className="grid grid-cols-4 gap-2">
              {colors.map((colorOption) => (
                <button
                  key={colorOption}
                  type="button"
                  onClick={() => setColor(colorOption)}
                  className={`w-12 h-12 rounded-lg border-2 ${
                    color === colorOption ? 'border-gray-900' : 'border-gray-300'
                  }`}
                  style={{ backgroundColor: colorOption }}
                />
              ))}
            </div>
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Folder'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Main App Component
const App = () => {
  const [showRegister, setShowRegister] = useState(false);

  return (
    <AuthProvider>
      <AppContent 
        showRegister={showRegister}
        setShowRegister={setShowRegister}
      />
    </AuthProvider>
  );
};

const AppContent = ({ showRegister, setShowRegister }) => {
  const { user, loading, masterPasswordVerified } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return showRegister ? (
      <RegisterForm onSwitchToLogin={() => setShowRegister(false)} />
    ) : (
      <LoginForm onSwitchToRegister={() => setShowRegister(true)} />
    );
  }

  if (!masterPasswordVerified) {
    return <MasterPasswordSetup />;
  }

  return <PasswordManager />;
};

export default App;