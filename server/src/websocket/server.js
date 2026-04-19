import { randomUUID } from "crypto";
import { WebSocketServer } from "ws";
import Room from "../models/Room.js";
import { verifyToken } from "../utils/jwt.js";
import logger from "../utils/logger.js";
import { handleMessage } from "./messageHandler.js";

class SignalingServer {
  constructor(server) {
    this.wss = new WebSocketServer({
      server,
      path: "/ws",
      // SEC-003: Validate WebSocket origin to prevent cross-site WebSocket hijacking
      verifyClient: (info, callback) => {
        const origin = info.origin || info.req.headers.origin;
        const allowedOrigins = (process.env.CLIENT_URL || "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);

        // In development, also allow common localhost origins
        if (process.env.NODE_ENV !== "production") {
          allowedOrigins.push(
            "http://localhost:5173",
            "http://localhost:3000",
            "http://127.0.0.1:5173"
          );
        }

        if (!origin || !allowedOrigins.includes(origin)) {
          logger.warn("WebSocket connection rejected: invalid origin", {
            origin,
          });
          callback(false, 403, "Forbidden: invalid origin");
          return;
        }
        callback(true);
      },
      maxPayload: 64 * 1024, // SEC-003: 64KB max WebSocket message size
    });

    this.clients = new Map();
    this.userConnections = new Map();
    this.rooms = new Map();
    this.messageRateLimits = new Map();

    this.setupWebSocketServer();

    // MEM-001: Periodic cleanup of stale connections and orphaned data
    this.cleanupInterval = setInterval(() => {
      this.cleanupStaleConnections();
    }, 60000);

    // ERR-002: Ping interval for dead connection detection
    this.pingInterval = setInterval(() => {
      this.pingAllClients();
    }, 30000);
  }

  setupWebSocketServer() {
    this.wss.on("connection", (ws, req) => {
      logger.info("New WebSocket connection attempt");

      const url = new URL(req.url, `http://${req.headers.host}`);
      // AUDIT: Only accept 'ticket' parameter to enforce short-lived ticket model.
      // Accepting 'token' would allow long-lived access tokens to bypass the 30s ticket expiry.
      const token = url.searchParams.get("ticket");

      if (!token) {
        logger.warn("WebSocket connection rejected: No token provided");
        ws.close(1008, "Authentication required");
        return;
      }

      try {
        const decoded = verifyToken(token);
        const connectionId = this.generateConnectionId();

        const client = {
          ws,
          userId: decoded.id,
          roomId: null,
          username: null,
          connectionId,
        };

        this.clients.set(connectionId, client);

        if (!this.userConnections.has(client.userId)) {
          this.userConnections.set(client.userId, new Set());
        }
        this.userConnections.get(client.userId).add(connectionId);

        // ERR-002: Mark connection as alive for ping/pong dead-connection detection
        ws.isAlive = true;
        ws.on("pong", () => {
          ws.isAlive = true;
        });

        logger.info("WebSocket authenticated", {
          userId: decoded.id,
          connectionId,
        });

        ws.on("message", (data) => {
          try {
            const message = JSON.parse(data.toString());
            this.handleMessage(client, message);
          } catch (error) {
            logger.error("Error parsing message", { error: error.message });
            this.sendError(ws, "Invalid message format");
          }
        });

        ws.on("close", () => {
          this.handleDisconnect(client).catch((error) => {
            logger.error("WebSocket disconnect handler error", {
              userId: client.userId,
              connectionId: client.connectionId,
              error: error.message,
            });
          });
        });

        ws.on("error", (error) => {
          logger.error("WebSocket error", {
            userId: client.userId,
            connectionId: client.connectionId,
            error: error.message,
          });
        });

        this.send(ws, {
          type: "connected",
          userId: decoded.id,
          connectionId,
        });
      } catch (error) {
        logger.warn("WebSocket authentication failed", {
          error: error.message,
        });
        ws.close(1008, "Invalid token");
      }
    });

    logger.info("WebSocket signaling server initialized");
  }

  // ERR-002: Ping all clients to detect dead connections (browser crash, network drop)
  pingAllClients() {
    this.wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        logger.warn("Terminating unresponsive WebSocket connection");
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }

  // MEM-001: Clean up stale connections and orphaned map entries
  cleanupStaleConnections() {
    let cleaned = 0;

    this.clients.forEach((client, connectionId) => {
      if (
        client.ws.readyState === client.ws.CLOSED ||
        client.ws.readyState === client.ws.CLOSING
      ) {
        this.handleDisconnect(client).catch((err) => {
          logger.error("Cleanup disconnect error", {
            connectionId,
            error: err.message,
          });
        });
        cleaned++;
      }
    });

    // MEM-001: Clean orphaned rate limit entries
    this.messageRateLimits.forEach((_, key) => {
      if (!this.clients.has(key)) {
        this.messageRateLimits.delete(key);
      }
    });

    if (cleaned > 0) {
      logger.info("Cleaned stale connections", { count: cleaned });
    }
  }

  handleMessage(client, message) {
    const correlationId =
      message.correlationId || this.generateCorrelationId();

    // Rate limiting: Max 100 messages per minute per connection
    const now = Date.now();
    const rateLimitKey = client.connectionId;

    if (!this.messageRateLimits.has(rateLimitKey)) {
      this.messageRateLimits.set(rateLimitKey, []);
    }

    const timestamps = this.messageRateLimits.get(rateLimitKey);

    // Remove timestamps older than 1 minute
    const oneMinuteAgo = now - 60000;
    const recentTimestamps = timestamps.filter((t) => t > oneMinuteAgo);

    // Check rate limit (100 messages per minute)
    if (recentTimestamps.length >= 100) {
      logger.warn("Rate limit exceeded", {
        userId: client.userId,
        connectionId: client.connectionId,
        messageCount: recentTimestamps.length,
      });
      this.sendError(
        client.ws,
        "Rate limit exceeded. Please slow down.",
        correlationId
      );
      return;
    }

    // Add current timestamp
    recentTimestamps.push(now);
    this.messageRateLimits.set(rateLimitKey, recentTimestamps);

    logger.debug("Received message", {
      type: message.type,
      userId: client.userId,
      connectionId: client.connectionId,
      roomId: client.roomId,
      correlationId,
    });

    handleMessage(this, client, message, correlationId);
  }

  async handleDisconnect(client) {
    if (client.roomId) {
      await this.leaveRoom(client);
    }

    this.clients.delete(client.connectionId);

    // MEM-001: Clean up rate limit data for disconnected clients
    this.messageRateLimits.delete(client.connectionId);

    const connections = this.userConnections.get(client.userId);
    if (connections) {
      connections.delete(client.connectionId);
      if (connections.size === 0) {
        this.userConnections.delete(client.userId);
      }
    }

    logger.info("Client disconnected", {
      userId: client.userId,
      username: client.username,
      connectionId: client.connectionId,
    });
  }

  async leaveRoom(
    client,
    { notifyClient = false, correlationId = null } = {}
  ) {
    if (!client.roomId) return;

    const roomId = client.roomId;
    const roomConnections = this.rooms.get(roomId);

    if (roomConnections) {
      roomConnections.delete(client.connectionId);

      if (roomConnections.size === 0) {
        this.rooms.delete(roomId);
        logger.info("Room closed (empty)", { roomId });
      } else {
        this.broadcastToRoom(
          roomId,
          {
            type: "user-left",
            userId: client.userId,
            username: client.username,
            connectionId: client.connectionId,
            correlationId,
          },
          client.connectionId
        );
      }
    }

    try {
      await this.updateRoomOnLeave(roomId, client);
    } catch (error) {
      logger.error("Room leave persistence error", {
        roomId,
        userId: client.userId,
        connectionId: client.connectionId,
        error: error.message,
      });
    }

    client.roomId = null;

    if (notifyClient) {
      this.send(client.ws, {
        type: "room-left",
        roomId,
        connectionId: client.connectionId,
        correlationId,
      });
    }
  }

  send(ws, message) {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  sendError(ws, message, correlationId = null) {
    this.send(ws, {
      type: "error",
      message,
      correlationId,
    });
  }

  broadcastToRoom(roomId, message, excludeConnectionId = null) {
    const room = this.rooms.get(roomId);
    if (!room) return;

    room.forEach((connectionId) => {
      if (connectionId !== excludeConnectionId) {
        const client = this.clients.get(connectionId);
        if (client) {
          this.send(client.ws, message);
        }
      }
    });
  }

  sendToUser(userId, message) {
    const connections = this.userConnections.get(userId);
    if (!connections) return;

    connections.forEach((connectionId) => {
      const client = this.clients.get(connectionId);
      if (client) {
        this.send(client.ws, message);
      }
    });
  }

  sendToConnection(connectionId, message) {
    const client = this.clients.get(connectionId);
    if (client) {
      this.send(client.ws, message);
    }
  }

  getRoomParticipants(roomId) {
    const room = this.rooms.get(roomId);
    if (!room) return [];

    return Array.from(room)
      .map((connectionId) => {
        const client = this.clients.get(connectionId);
        if (!client) return null;

        return {
          connectionId,
          userId: client.userId,
          username: client.username,
        };
      })
      .filter(Boolean);
  }

  getUniqueRoomUsers(roomId) {
    const participants = this.getRoomParticipants(roomId);
    const unique = new Map();

    participants.forEach((participant) => {
      if (!unique.has(participant.userId)) {
        unique.set(participant.userId, participant);
      }
    });

    return Array.from(unique.values());
  }

  getUniqueRoomUserCount(roomId) {
    return this.getUniqueRoomUsers(roomId).length;
  }

  assignClientToRoom(client, roomId) {
    if (!this.rooms.has(roomId)) {
      this.rooms.set(roomId, new Set());
    }

    const roomConnections = this.rooms.get(roomId);
    roomConnections.add(client.connectionId);
    client.roomId = roomId;
  }

  async registerRoomJoin(roomDoc, client) {
    this.assignClientToRoom(client, roomDoc.roomId);

    // AUDIT: Cap participant history to prevent unbounded document growth.
    // Keep all active (no leftAt) entries and the most recent 200 historical entries.
    if (roomDoc.participants.length > 500) {
      const active = roomDoc.participants.filter((p) => !p.leftAt);
      const historical = roomDoc.participants
        .filter((p) => p.leftAt)
        .slice(-200);
      roomDoc.participants = [...historical, ...active];
    }

    roomDoc.participants.push({
      userId: client.userId,
      connectionId: client.connectionId,
      joinedAt: new Date(),
    });

    roomDoc.currentParticipants = this.getUniqueRoomUserCount(roomDoc.roomId);
    await roomDoc.save();
  }

  async updateRoomOnLeave(roomId, client) {
    const roomDoc = await Room.findOne({ roomId });
    if (!roomDoc) {
      logger.warn("Room document not found during leave", {
        roomId,
        userId: client.userId,
        connectionId: client.connectionId,
      });
      return;
    }

    const participant = roomDoc.participants
      .slice()
      .reverse()
      .find((entry) => {
        if (entry.connectionId) {
          return (
            entry.connectionId === client.connectionId && !entry.leftAt
          );
        }
        return (
          entry.userId?.toString() === client.userId.toString() &&
          !entry.leftAt
        );
      });

    if (participant && !participant.leftAt) {
      participant.leftAt = new Date();
      participant.duration = Math.max(
        0,
        Math.floor((participant.leftAt - participant.joinedAt) / 1000)
      );
    }

    roomDoc.currentParticipants = this.getUniqueRoomUserCount(roomId);

    // Auto-close room when it becomes empty
    if (roomDoc.currentParticipants === 0 && roomDoc.isActive) {
      roomDoc.isActive = false;
      roomDoc.closedAt = new Date();
      logger.info("Room auto-closed (all participants left)", { roomId });
    }

    await roomDoc.save();
  }

  // MEM-001: Cleanup method for graceful shutdown
  destroy() {
    clearInterval(this.cleanupInterval);
    clearInterval(this.pingInterval);
  }

  generateCorrelationId() {
    return randomUUID();
  }

  generateConnectionId() {
    return randomUUID();
  }
}

export default SignalingServer;
