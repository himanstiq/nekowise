// SEC-001: Use relative path so requests go through the Vite proxy (same-origin),
// ensuring httpOnly cookies are sent correctly without cross-origin issues
const API_URL = import.meta.env.VITE_API_URL || "/api";

class ApiService {
  constructor() {
    this.baseURL = API_URL;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;

    const config = {
      ...options,
      credentials: "include", // SEC-001: Send httpOnly cookies with every request
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Something went wrong");
      }

      return data;
    } catch (error) {
      console.error("API Error:", error);
      throw error;
    }
  }

  async register(userData) {
    return this.request("/auth/register", {
      method: "POST",
      body: JSON.stringify(userData),
    });
  }

  async login(credentials) {
    return this.request("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  }

  async getMe() {
    return this.request("/auth/me");
  }

  // SEC-001: Refresh now relies on httpOnly cookie — no body payload needed
  async refreshToken() {
    return this.request("/auth/refresh", {
      method: "POST",
    });
  }

  // SEC-001: Server-side logout clears httpOnly cookies
  async logout() {
    return this.request("/auth/logout", {
      method: "POST",
    });
  }

  async createRoom(roomData) {
    return this.request("/rooms", {
      method: "POST",
      body: JSON.stringify(roomData),
    });
  }

  async getRooms(query = {}) {
    const params = new URLSearchParams(query).toString();
    return this.request(`/rooms${params ? `?${params}` : ""}`);
  }

  async getCompletedRooms(query = {}) {
    const params = new URLSearchParams(query).toString();
    return this.request(`/rooms/completed${params ? `?${params}` : ""}`);
  }

  async getRoomById(roomId) {
    return this.request(`/rooms/${roomId}`);
  }

  async validateRoomAccess(roomId, accessToken) {
    return this.request(`/rooms/${roomId}/validate`, {
      method: "POST",
      body: JSON.stringify({ accessToken }),
    });
  }

  async deleteRoom(roomId) {
    return this.request(`/rooms/${roomId}`, {
      method: "DELETE",
    });
  }
}

export default new ApiService();
