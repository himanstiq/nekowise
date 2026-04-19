import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

// AUDIT: Added requireAdmin prop to enforce admin role at the route level,
// preventing non-admin users from mounting admin components.
export default function ProtectedRoute({ children, requireAdmin = false }) {
  const { user, isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-xl">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // AUDIT: Block non-admin users from accessing admin routes
  if (requireAdmin && user?.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}
