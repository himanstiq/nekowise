import logger from "../utils/logger.js";
import User from "../models/User.js";
import Room from "../models/Room.js";

// DATA-002: Per-room mutex to prevent race conditions on concurrent joins
const roomJoinLocks = new Map();

function acquireRoomLock(roomId) {
  if (!roomJoinLocks.has(roomId)) {
    roomJoinLocks.set(roomId, Promise.resolve());
  }
  let release;
  const prevLock = roomJoinLocks.get(roomId);
  const newLock = new Promise((resolve) => {
    release = resolve;
  });
  roomJoinLocks.set(roomId, newLock);
  return prevLock.then(() => release);
}

// AUDIT: Clean up stale room lock entries to prevent memory leak
export function releaseRoomLock(roomId) {
  roomJoinLocks.delete(roomId);
}

// SEC-006: Improved chat message sanitization — strip control chars instead of naive regex
function sanitizeChatMessage(text) {
  return text
    .trim()
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // Strip control characters
    .substring(0, 500); // Enforce length limit
}

export async function handleMessage(server, client, message, correlationId) {
  const { type } = message;

  const handlers = {
    "join-room": handleJoinRoom,
    "leave-room": handleLeaveRoom,
    offer: handleOffer,
    answer: handleAnswer,
    "ice-candidate": handleIceCandidate,
    "screen-share-started": handleScreenShareStarted,
    "screen-share-stopped": handleScreenShareStopped,
    "chat-message": handleChatMessage,
    typing: handleTyping,
    reaction: handleReaction,
    ping: handlePing,
  };

  const handler = handlers[type];
  if (handler) {
    try {
      await handler(server, client, message, correlationId);
    } catch (error) {
      logger.error("Message handler error", {
        type,
        userId: client.userId,
        error: error.message,
        correlationId,
      });
      server.sendError(client.ws, error.message, correlationId);
    }
  } else {
    logger.warn("Unknown message type", { type, userId: client.userId });
    server.sendError(client.ws, "Unknown message type", correlationId);
  }
}

async function handleJoinRoom(server, client, message, correlationId) {
  const { roomId, username } = message;

  if (!roomId) {
    throw new Error("Room ID is required");
  }

  // SEC-004: Validate roomId type to prevent NoSQL injection
  if (typeof roomId !== "string") {
    throw new Error("Invalid room ID");
  }

  // DATA-002: Acquire per-room lock to prevent concurrent join race conditions
  const release = await acquireRoomLock(roomId);
  try {
    const room = await Room.findOne({ roomId, isActive: true });

    if (!room) {
      throw new Error("Room not found");
    }

    if (room.currentParticipants >= room.maxParticipants) {
      throw new Error("Room is full");
    }

    const user = await User.findById(client.userId);
    if (!user) {
      throw new Error("User not found");
    }

    // If client is in a different room, leave that room first
    if (client.roomId && client.roomId !== roomId) {
      await server.leaveRoom(client);
    }

    // If already in this room, refresh participant list
    if (client.roomId === roomId) {
      // AUDIT: Always use server-fetched username to prevent spoofing
      client.username = user.displayName || user.username;

      const participants = server
        .getRoomParticipants(roomId)
        .filter((p) => p.connectionId !== client.connectionId);

      server.send(client.ws, {
        type: "room-joined",
        roomId,
        participants,
        correlationId,
      });
      return;
    }

    // AUDIT: Always use server-fetched username to prevent spoofing
    client.username = user.displayName || user.username;

    await server.registerRoomJoin(room, client);

    const participants = server.getRoomParticipants(roomId);

    server.send(client.ws, {
      type: "room-joined",
      roomId,
      participants: participants.filter(
        (p) => p.connectionId !== client.connectionId
      ),
      correlationId,
    });

    server.broadcastToRoom(
      roomId,
      {
        type: "user-joined",
        userId: client.userId,
        username: client.username,
        connectionId: client.connectionId,
      },
      client.connectionId
    );

    logger.info("User joined room", {
      userId: client.userId,
      username: client.username,
      roomId,
      connectionId: client.connectionId,
      participantCount: server.getUniqueRoomUserCount(roomId),
      correlationId,
    });
  } finally {
    // DATA-002: Always release the lock, even on error
    release();
  }
}

async function handleLeaveRoom(server, client, message, correlationId) {
  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  const roomId = client.roomId;
  await server.leaveRoom(client, { notifyClient: true, correlationId });

  logger.info("User left room", {
    userId: client.userId,
    username: client.username,
    roomId,
    connectionId: client.connectionId,
    correlationId,
  });
}

async function handleOffer(server, client, message, correlationId) {
  const { targetUserId, targetConnectionId, offer } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  if (!offer) {
    throw new Error("Offer is required");
  }

  const targets = resolveTargets(server, client, {
    targetUserId,
    targetConnectionId,
  });

  if (targets.length === 0) {
    throw new Error("Target not in the same room");
  }

  targets.forEach((targetClient) => {
    server.send(targetClient.ws, {
      type: "offer",
      fromUserId: client.userId,
      fromUsername: client.username,
      fromConnectionId: client.connectionId,
      offer,
      correlationId,
    });
  });

  logger.debug("Offer relayed", {
    fromUserId: client.userId,
    fromConnectionId: client.connectionId,
    toUserId: targetUserId,
    toConnectionId: targetConnectionId,
    roomId: client.roomId,
    correlationId,
  });
}

async function handleAnswer(server, client, message, correlationId) {
  const { targetUserId, targetConnectionId, answer } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  if (!answer) {
    throw new Error("Answer is required");
  }

  const targets = resolveTargets(server, client, {
    targetUserId,
    targetConnectionId,
  });

  if (targets.length === 0) {
    throw new Error("Target not in the same room");
  }

  targets.forEach((targetClient) => {
    server.send(targetClient.ws, {
      type: "answer",
      fromUserId: client.userId,
      fromUsername: client.username,
      fromConnectionId: client.connectionId,
      answer,
      correlationId,
    });
  });

  logger.debug("Answer relayed", {
    fromUserId: client.userId,
    fromConnectionId: client.connectionId,
    toUserId: targetUserId,
    toConnectionId: targetConnectionId,
    roomId: client.roomId,
    correlationId,
  });
}

async function handleIceCandidate(server, client, message, correlationId) {
  const { targetUserId, targetConnectionId, candidate } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  if (!candidate) {
    throw new Error("ICE candidate is required");
  }

  const targets = resolveTargets(server, client, {
    targetUserId,
    targetConnectionId,
  });

  if (targets.length === 0) {
    throw new Error("Target not in the same room");
  }

  targets.forEach((targetClient) => {
    server.send(targetClient.ws, {
      type: "ice-candidate",
      fromUserId: client.userId,
      fromConnectionId: client.connectionId,
      candidate,
      correlationId,
    });
  });

  logger.debug("ICE candidate relayed", {
    fromUserId: client.userId,
    fromConnectionId: client.connectionId,
    toUserId: targetUserId,
    toConnectionId: targetConnectionId,
    roomId: client.roomId,
    correlationId,
  });
}

async function handleScreenShareStarted(
  server,
  client,
  message,
  correlationId
) {
  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  server.broadcastToRoom(
    client.roomId,
    {
      type: "screen-share-started",
      userId: client.userId,
      username: client.username,
      connectionId: client.connectionId,
      correlationId,
    },
    client.connectionId
  );

  logger.info("Screen share started", {
    userId: client.userId,
    roomId: client.roomId,
    connectionId: client.connectionId,
    correlationId,
  });
}

async function handleScreenShareStopped(
  server,
  client,
  message,
  correlationId
) {
  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  server.broadcastToRoom(
    client.roomId,
    {
      type: "screen-share-stopped",
      userId: client.userId,
      username: client.username,
      connectionId: client.connectionId,
      correlationId,
    },
    client.connectionId
  );

  logger.info("Screen share stopped", {
    userId: client.userId,
    roomId: client.roomId,
    connectionId: client.connectionId,
    correlationId,
  });
}

async function handlePing(server, client, message, correlationId) {
  server.send(client.ws, {
    type: "pong",
    timestamp: Date.now(),
    correlationId,
  });
}

async function handleChatMessage(server, client, message, correlationId) {
  const { text } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  if (!text || typeof text !== "string" || text.trim().length === 0) {
    throw new Error("Message text is required");
  }

  if (text.length > 500) {
    throw new Error("Message too long (max 500 characters)");
  }

  // SEC-006: Use improved sanitization — strip control characters instead of
  // naive regex that can be bypassed with mixed case or whitespace insertion
  const sanitizedText = sanitizeChatMessage(text);

  if (sanitizedText.length === 0) {
    throw new Error("Message contains invalid characters");
  }

  const messageId = Date.now() + Math.random().toString(36).substr(2, 9);

  // Broadcast to room excluding the sender (they already added it to their UI optimistically)
  server.broadcastToRoom(
    client.roomId,
    {
      type: "chat-message",
      messageId,
      fromUserId: client.userId,
      fromUsername: client.username,
      text: sanitizedText,
      timestamp: Date.now(),
      correlationId,
    },
    client.connectionId
  );

  logger.info("Chat message sent", {
    userId: client.userId,
    roomId: client.roomId,
    messageLength: sanitizedText.length,
    correlationId,
  });
}

async function handleTyping(server, client, message, correlationId) {
  const { isTyping } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  server.broadcastToRoom(
    client.roomId,
    {
      type: "typing",
      userId: client.userId,
      username: client.username,
      isTyping: !!isTyping,
      correlationId,
    },
    client.connectionId
  );
}

async function handleReaction(server, client, message, correlationId) {
  const { emoji } = message;

  if (!client.roomId) {
    throw new Error("Not in a room");
  }

  if (!emoji || typeof emoji !== "string" || emoji.length === 0) {
    throw new Error("Emoji is required");
  }

  // Broadcast reaction to all room participants including sender
  // (so they can see their own reaction animation)
  server.broadcastToRoom(client.roomId, {
    type: "reaction",
    userId: client.userId,
    username: client.username,
    emoji: emoji.substring(0, 10), // Limit emoji length
    timestamp: Date.now(),
    correlationId,
  });

  logger.debug("Reaction sent", {
    userId: client.userId,
    roomId: client.roomId,
    emoji,
    correlationId,
  });
}

function resolveTargets(server, client, { targetUserId, targetConnectionId }) {
  const targets = [];

  if (targetConnectionId) {
    const targetClient = server.clients.get(targetConnectionId);
    if (targetClient && targetClient.roomId === client.roomId) {
      targets.push(targetClient);
    }
  } else if (targetUserId) {
    const connections = server.userConnections?.get(targetUserId);
    if (connections) {
      connections.forEach((connectionId) => {
        const targetClient = server.clients.get(connectionId);
        if (targetClient && targetClient.roomId === client.roomId) {
          targets.push(targetClient);
        }
      });
    }
  }

  return targets;
}
