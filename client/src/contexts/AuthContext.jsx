import { createContext, useContext, useState, useEffect } from "react";
import api from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // SEC-001: Check auth via httpOnly cookie — no localStorage token check needed
  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      // SEC-001: Cookie is sent automatically via credentials:'include' in api.js
      const response = await api.getMe();
      setUser(response.user);
    } catch (error) {
      // No valid session — user is not authenticated
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials) => {
    // SEC-001: Server sets httpOnly cookies — no tokens in response body
    const response = await api.login(credentials);
    setUser(response.user);
    return response;
  };

  const register = async (userData) => {
    // SEC-001: Server sets httpOnly cookies — no tokens in response body
    const response = await api.register(userData);
    setUser(response.user);
    return response;
  };

  // SEC-001: Server-side logout clears httpOnly cookies
  const logout = async () => {
    try {
      await api.logout();
    } catch (error) {
      // Best-effort — clear client state even if server call fails
      console.error("Logout API call failed:", error);
    }
    setUser(null);
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

export default AuthContext;
