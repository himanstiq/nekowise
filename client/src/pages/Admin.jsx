import { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import Container from "../components/Layout/Container";
import { Button } from "../components/ui/button";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import api from "../services/api";
import {
  Video,
  ArrowLeft,
  Users,
  Home,
  VideoIcon,
  HardDrive,
  Clock,
  Monitor,
  Settings,
  Trash2,
  Shield,
  ShieldAlert,
} from "lucide-react";

export default function Admin() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [activeRooms, setActiveRooms] = useState([]);
  const [recentSessions, setRecentSessions] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  useEffect(() => {
    if (!user || user.role !== "admin") {
      navigate("/dashboard");
      return;
    }

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, [user, navigate]);

  const fetchData = async () => {
    try {
      setLoading(true);
      // AUDIT: Use api.request() — api.get/post/put/delete don't exist on ApiService
      const [statsRes, roomsRes, sessionsRes, usersRes] = await Promise.all([
        api.request("/admin/stats"),
        api.request("/admin/rooms/active"),
        api.request("/admin/sessions/recent?limit=10"),
        api.request("/admin/users?limit=50"),
      ]);

      // AUDIT: api.request() returns parsed JSON directly, not { data: ... }
      setStats(statsRes.stats);
      setActiveRooms(roomsRes.rooms);
      setRecentSessions(sessionsRes.sessions);
      setUsers(usersRes.users);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch admin data:", err);
      setError(err.message || "Failed to load admin data");
    } finally {
      setLoading(false);
    }
  };

  const handleCloseRoom = async (roomId) => {
    if (!confirm("Are you sure you want to close this room?")) return;

    try {
      // AUDIT: Use api.request() with method option
      await api.request(`/admin/rooms/${roomId}/close`, { method: "POST" });
      fetchData();
    } catch (err) {
      alert(err.message || "Failed to close room");
    }
  };

  const handleUpdateRole = async (userId, newRole) => {
    if (!confirm(`Change user role to ${newRole}?`)) return;

    try {
      // AUDIT: Use api.request() with method and body options
      await api.request(`/admin/users/${userId}/role`, {
        method: "PUT",
        body: JSON.stringify({ role: newRole }),
      });
      fetchData();
    } catch (err) {
      alert(err.message || "Failed to update role");
    }
  };

  const handleDeleteUser = async (userId) => {
    if (
      !confirm(
        "Are you sure you want to delete this user? This cannot be undone."
      )
    )
      return;

    try {
      // AUDIT: Use api.request() with DELETE method
      await api.request(`/admin/users/${userId}`, { method: "DELETE" });
      fetchData();
    } catch (err) {
      alert(err.message || "Failed to delete user");
    }
  };

  if (loading && !stats) {
    return (
      <Container>
        <div className="text-center py-12">
          <div className="text-xl text-on-surface-variant">
            Loading admin panel...
          </div>
        </div>
      </Container>
    );
  }

  if (error) {
    return (
      <Container>
        <div className="text-center py-12">
          <div className="text-xl text-destructive">Error: {error}</div>
          <button
            onClick={fetchData}
            className="mt-4 bg-primary text-on-primary px-6 py-2 rounded-2xl shadow-sm hover:bg-primary/90 transition-all"
          >
            Retry
          </button>
        </div>
      </Container>
    );
  }

  return (
    <Container>
      <div className="max-w-7xl mx-auto py-8 px-4">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-12 h-12 rounded-2xl bg-primary/10">
              <span className="material-symbols-outlined text-primary text-3xl">
                hub
              </span>
            </div>
            <div>
              <h1 className="text-3xl font-bold font-display">
                Nekowise Admin
              </h1>
              <p className="text-on-surface-variant text-sm">
                System Dashboard
              </p>
            </div>
          </div>
          <Button variant="outline" onClick={() => navigate("/dashboard")}>
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </div>

        {/* Stats Overview */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard
              title="Total Users"
              value={stats.users.total}
              subtitle={`${stats.users.active} active`}
              icon={<Users className="h-6 w-6" />}
            />
            <StatCard
              title="Active Rooms"
              value={stats.rooms.active}
              subtitle={`${stats.rooms.total} total`}
              icon={<Home className="h-6 w-6" />}
            />
            <StatCard
              title="Active Sessions"
              value={stats.sessions.active}
              subtitle={`${stats.sessions.total} total`}
              icon={<VideoIcon className="h-6 w-6" />}
            />
            <StatCard
              title="Server Memory"
              value={`${stats.system.memory.heapUsed}MB`}
              subtitle={`of ${stats.system.memory.heapTotal}MB`}
              icon={<HardDrive className="h-6 w-6" />}
            />
          </div>
        )}

        {/* System Info */}
        {stats && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Monitor className="h-5 w-5" />
                System Information
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Uptime
                  </div>
                  <div className="font-medium mt-1">
                    {Math.floor(stats.system.uptime / 3600)}h{" "}
                    {Math.floor((stats.system.uptime % 3600) / 60)}m
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Platform</div>
                  <div className="font-medium mt-1">
                    {stats.system.platform}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Node Version</div>
                  <div className="font-medium mt-1">
                    {stats.system.nodeVersion}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground">Memory RSS</div>
                  <div className="font-medium mt-1">
                    {stats.system.memory.rss}MB
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b">
          <Button
            onClick={() => setActiveTab("overview")}
            variant={activeTab === "overview" ? "default" : "ghost"}
            size="sm"
            className="rounded-b-none"
          >
            Active Rooms
          </Button>
          <Button
            onClick={() => setActiveTab("sessions")}
            variant={activeTab === "sessions" ? "default" : "ghost"}
            size="sm"
            className="rounded-b-none"
          >
            Recent Sessions
          </Button>
          <Button
            onClick={() => setActiveTab("users")}
            variant={activeTab === "users" ? "default" : "ghost"}
            size="sm"
            className="rounded-b-none"
          >
            Users
          </Button>
        </div>

        {/* Active Rooms Tab */}
        {activeTab === "overview" && (
          <div>
            <h2 className="text-2xl font-semibold mb-4">
              Active Rooms ({activeRooms.length})
            </h2>
            {activeRooms.length === 0 ? (
              <div className="text-muted-foreground text-center py-12">
                No active rooms
              </div>
            ) : (
              <div className="space-y-4">
                {activeRooms.map((room) => (
                  <Card key={room._id}>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <h3 className="text-lg font-semibold mb-2">
                            {room.name}
                          </h3>
                          <div className="space-y-1 text-sm text-muted-foreground">
                            <p>
                              Room ID:{" "}
                              <span className="font-mono">{room.roomId}</span>
                            </p>
                            <p className="flex items-center gap-2">
                              <Users className="h-4 w-4" />
                              Participants: {room.currentParticipants} /{" "}
                              {room.maxParticipants}
                            </p>
                            <p>
                              Created by:{" "}
                              {room.createdBy?.username || "Unknown"}
                            </p>
                            <p>
                              Created:{" "}
                              {new Date(room.createdAt).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        <Button
                          onClick={() => handleCloseRoom(room.roomId)}
                          variant="destructive"
                        >
                          Close Room
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Recent Sessions Tab */}
        {activeTab === "sessions" && (
          <div>
            <h2 className="text-2xl font-semibold mb-4">Recent Sessions</h2>
            {recentSessions.length === 0 ? (
              <div className="text-muted-foreground text-center py-12">
                No sessions yet
              </div>
            ) : (
              <div className="space-y-4">
                {recentSessions.map((session) => (
                  <Card key={session._id}>
                    <CardContent className="pt-6">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold">
                          {session.roomName}
                        </h3>
                        <Badge
                          variant={session.isActive ? "success" : "secondary"}
                        >
                          {session.isActive ? "Active" : "Ended"}
                        </Badge>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <div className="text-muted-foreground">Duration</div>
                          <div className="font-medium">
                            {session.totalDuration
                              ? `${Math.floor(session.totalDuration / 60)}m ${
                                  session.totalDuration % 60
                                }s`
                              : "Ongoing"}
                          </div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">
                            Peak Participants
                          </div>
                          <div className="font-medium">
                            {session.peakParticipants}
                          </div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Messages</div>
                          <div className="font-medium">
                            {session.stats.totalMessages}
                          </div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Started</div>
                          <div className="font-medium">
                            {new Date(session.startedAt).toLocaleString()}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Users Tab */}
        {activeTab === "users" && (
          <div>
            <h2 className="text-2xl font-semibold mb-4">
              Users ({users.length})
            </h2>
            {users.length === 0 ? (
              <div className="text-muted-foreground text-center py-12">
                No users found
              </div>
            ) : (
              <Card>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b">
                      <tr className="text-muted-foreground">
                        <th className="px-4 py-3 font-medium">Username</th>
                        <th className="px-4 py-3 font-medium">Email</th>
                        <th className="px-4 py-3 font-medium">Role</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Created</th>
                        <th className="px-4 py-3 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((u) => (
                        <tr key={u._id} className="border-b hover:bg-muted/50">
                          <td className="px-4 py-3 font-medium">
                            {u.username}
                          </td>
                          <td className="px-4 py-3">{u.email}</td>
                          <td className="px-4 py-3">
                            <Badge
                              variant={
                                u.role === "admin" ? "default" : "secondary"
                              }
                            >
                              {u.role === "admin" && (
                                <Shield className="h-3 w-3 mr-1" />
                              )}
                              {u.role}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            <Badge
                              variant={u.isActive ? "success" : "destructive"}
                            >
                              {u.isActive ? "Active" : "Inactive"}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            {new Date(u.createdAt).toLocaleDateString()}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2">
                              <Button
                                onClick={() =>
                                  handleUpdateRole(
                                    u._id,
                                    u.role === "admin" ? "user" : "admin"
                                  )
                                }
                                size="sm"
                                variant="outline"
                                disabled={u._id === user._id}
                              >
                                {u.role === "admin" ? (
                                  <>
                                    <ShieldAlert className="h-3 w-3" />
                                    Remove Admin
                                  </>
                                ) : (
                                  <>
                                    <Shield className="h-3 w-3" />
                                    Make Admin
                                  </>
                                )}
                              </Button>
                              <Button
                                onClick={() => handleDeleteUser(u._id)}
                                size="sm"
                                variant="destructive"
                                disabled={u._id === user._id}
                              >
                                <Trash2 className="h-3 w-3" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </div>
        )}
      </div>
    </Container>
  );
}

function StatCard({ title, value, subtitle, icon }) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium text-muted-foreground">{title}</h3>
          <div className="text-primary">{icon}</div>
        </div>
        <div className="text-3xl font-bold mb-1">{value}</div>
        <div className="text-sm text-muted-foreground">{subtitle}</div>
      </CardContent>
    </Card>
  );
}
