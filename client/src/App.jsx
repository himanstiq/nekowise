import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { SignalingProvider } from "./contexts/SignalingContext";
import ErrorBoundary from "./components/ErrorBoundary";
import Header from "./components/Layout/Header";
import Footer from "./components/Layout/Footer";
import ProtectedRoute from "./components/ProtectedRoute";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Room from "./pages/Room";
import Admin from "./pages/Admin";

function AppLayout() {
  const location = useLocation();
  const isHomePage = location.pathname === "/";

  return (
    <div className="flex flex-col min-h-screen">
      {!isHomePage && <Header />}
      <main className={isHomePage ? "" : "flex-1 bg-background"}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin"
            element={
              // AUDIT: Enforce admin role at route level to prevent non-admin UI rendering
              <ProtectedRoute requireAdmin>
                <Admin />
              </ProtectedRoute>
            }
          />
          <Route
            path="/room/:roomId"
            element={
              <ProtectedRoute>
                <ErrorBoundary>
                  <Room />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      {!isHomePage && <Footer />}
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <AuthProvider>
          <SignalingProvider>
            <AppLayout />
          </SignalingProvider>
        </AuthProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
}
