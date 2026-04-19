// SEC-001: Use relative URL so WebSocket goes through the Vite proxy (same-origin)
const WS_URL =
  import.meta.env.VITE_WS_URL ||
  `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws`;

// SEC-001: API URL for fetching short-lived WS tickets
const API_URL = import.meta.env.VITE_API_URL || "/api";

class WebSocketService {
  constructor() {
    this.ws = null;
    this.listeners = new Map();
    this.connectionStateListeners = new Set();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectInterval = 1000;
    this.maxReconnectInterval = 30000;
    this.heartbeatInterval = null;
    this.shouldReconnect = true;
    this.isConnecting = false;
    this.reconnectTimer = null; // MEM-004: Track reconnect timer for cleanup
  }

  // SEC-001: Fetch a short-lived ticket from the server instead of using localStorage token
  async connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN))
      return;

    this.isConnecting = true;
    this.shouldReconnect = true;
    this.notifyConnectionState("connecting");

    try {
      // SEC-001: Fetch a 30-second ticket via authenticated endpoint (cookie-based)
      const response = await fetch(`${API_URL}/auth/ws-ticket`, {
        method: "POST",
        credentials: "include", // SEC-001: Send httpOnly cookie
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        throw new Error("Failed to get WebSocket ticket");
      }

      const { ticket } = await response.json();
      this._connectWithTicket(ticket);
    } catch (error) {
      console.error("WebSocket ticket fetch failed:", error);
      this.isConnecting = false;
      this.notifyConnectionState("error");

      if (this.shouldReconnect) {
        this.scheduleReconnect();
      }
    }
  }

  // SEC-001: Connect using short-lived ticket instead of long-lived JWT in URL
  _connectWithTicket(ticket) {
    // SEC-012: Don't log the ticket
    console.log("Connecting to WebSocket:", WS_URL);
    const wsUrl = `${WS_URL}?ticket=${ticket}`;

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log("WebSocket connected");
      this.isConnecting = false;

      // ERR-001: Pass reconnected flag so consumers know to rejoin rooms
      const wasReconnect = this.reconnectAttempts > 0;
      this.reconnectAttempts = 0;
      this.notifyConnectionState("connected", {
        reconnected: wasReconnect,
      });
      this.startHeartbeat();
    };

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        this.handleMessage(message);
      } catch (error) {
        console.error("Error parsing message:", error);
      }
    };

    this.ws.onclose = (event) => {
      console.log("WebSocket disconnected:", event.code, event.reason);
      this.isConnecting = false;
      this.stopHeartbeat();
      this.notifyConnectionState("disconnected");

      if (
        this.shouldReconnect &&
        event.code !== 1000 &&
        event.code !== 1008
      ) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      this.isConnecting = false;
      this.notifyConnectionState("error");
    };
  }

  disconnect() {
    this.shouldReconnect = false;

    // MEM-004: Cancel any pending reconnection timer
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close(1000, "Client disconnect");
      this.ws = null;
    }

    this.notifyConnectionState("disconnected");
  }

  scheduleReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error("Max reconnection attempts reached");
      this.notifyConnectionState("failed");
      return;
    }

    const delay = Math.min(
      this.reconnectInterval * Math.pow(2, this.reconnectAttempts),
      this.maxReconnectInterval
    );

    this.reconnectAttempts++;
    console.log(
      `Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`
    );
    this.notifyConnectionState("reconnecting", {
      attempt: this.reconnectAttempts,
      delay,
    });

    // MEM-004: Store timer ID so disconnect() can cancel it
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      if (!this.shouldReconnect) return;
      // SEC-001: Fetches a fresh ticket internally
      await this.connect();
    }, delay);
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      this.send({ type: "ping" });
    }, 30000);
  }

  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn("WebSocket not connected, message not sent:", message.type);
    }
  }

  handleMessage(message) {
    const { type } = message;

    const listeners = this.listeners.get(type);
    if (listeners) {
      listeners.forEach((callback) => {
        try {
          callback(message);
        } catch (error) {
          console.error(`Error in listener for ${type}:`, error);
        }
      });
    }
  }

  on(messageType, callback) {
    if (!this.listeners.has(messageType)) {
      this.listeners.set(messageType, new Set());
    }
    this.listeners.get(messageType).add(callback);

    // Return unsubscribe function
    return () => {
      const listeners = this.listeners.get(messageType);
      if (listeners) {
        listeners.delete(callback);
        if (listeners.size === 0) {
          this.listeners.delete(messageType);
        }
      }
    };
  }

  // ERR-001: Connection state change now passes metadata (e.g., { reconnected: true })
  onConnectionStateChange(callback) {
    this.connectionStateListeners.add(callback);
    return () => {
      this.connectionStateListeners.delete(callback);
    };
  }

  notifyConnectionState(state, meta = {}) {
    this.connectionStateListeners.forEach((callback) => {
      try {
        callback(state, meta); // ERR-001: Pass metadata with state changes
      } catch (error) {
        console.error("Error in connection state listener:", error);
      }
    });
  }
}

export default new WebSocketService();
