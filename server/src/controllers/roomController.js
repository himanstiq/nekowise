import crypto from "crypto"; // AUDIT: Required for timing-safe comparison
import Room from "../models/Room.js";
import logger from "../utils/logger.js";

export const createRoom = async (req, res) => {
  try {
    const { name, description, isPublic, maxParticipants } = req.body;

    if (!name) {
      return res.status(400).json({ message: "Room name is required" });
    }

    // AUDIT: Validate and coerce maxParticipants before passing to model
    const safeMaxParticipants = Math.min(10, Math.max(2, parseInt(maxParticipants) || 6));

    const room = await Room.create({
      name,
      description,
      isPublic: isPublic || false,
      maxParticipants: safeMaxParticipants,
      createdBy: req.user.id,
    });

    await room.populate("createdBy", "username displayName avatar");

    logger.info("Room created", {
      roomId: room.roomId,
      createdBy: req.user.id,
    });

    res.status(201).json({
      success: true,
      message: "Room created successfully",
      room: {
        id: room._id,
        roomId: room.roomId,
        name: room.name,
        description: room.description,
        accessToken: room.accessToken, // Only returned on creation to creator
        isPublic: room.isPublic,
        maxParticipants: room.maxParticipants,
        currentParticipants: room.currentParticipants,
        createdBy: room.createdBy,
        createdAt: room.createdAt,
      },
    });
  } catch (error) {
    logger.error("Create room error", { error: error.message });
    // AUDIT: Never expose internal error details in production responses
    res.status(500).json({ message: "Error creating room" });
  }
};

export const getRooms = async (req, res) => {
  try {
    // AUDIT: Clamp pagination params to prevent resource exhaustion
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 10), 100);
    const { isPublic } = req.query;

    const query = { isActive: true };
    if (isPublic !== undefined) {
      query.isPublic = isPublic === "true";
    }

    const rooms = await Room.find(query)
      .populate("createdBy", "username displayName avatar")
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit);

    const count = await Room.countDocuments(query);

    res.status(200).json({
      success: true,
      rooms: rooms.map((room) => ({
        id: room._id,
        roomId: room.roomId,
        name: room.name,
        description: room.description,
        isPublic: room.isPublic,
        maxParticipants: room.maxParticipants,
        currentParticipants: room.currentParticipants,
        createdBy: room.createdBy,
        createdAt: room.createdAt,
        // accessToken intentionally excluded for security
      })),
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(count / limit),
        totalRooms: count,
      },
    });
  } catch (error) {
    logger.error("Get rooms error", { error: error.message });
    // AUDIT: Never expose internal error details
    res.status(500).json({ message: "Error fetching rooms" });
  }
};

export const getRoomById = async (req, res) => {
  try {
    const { roomId } = req.params;

    const room = await Room.findOne({ roomId, isActive: true })
      .populate("createdBy", "username displayName avatar")
      .populate("participants.userId", "username displayName avatar");

    if (!room) {
      return res.status(404).json({ message: "Room not found" });
    }

    res.status(200).json({
      success: true,
      room: {
        id: room._id,
        roomId: room.roomId,
        name: room.name,
        description: room.description,
        isPublic: room.isPublic,
        maxParticipants: room.maxParticipants,
        currentParticipants: room.currentParticipants,
        createdBy: room.createdBy,
        participants: room.participants,
        createdAt: room.createdAt,
        // Only include accessToken if user is the creator
        ...(room.createdBy._id.toString() === req.user.id && {
          accessToken: room.accessToken,
        }),
      },
    });
  } catch (error) {
    logger.error("Get room by ID error", { error: error.message });
    // AUDIT: Never expose internal error details
    res.status(500).json({ message: "Error fetching room" });
  }
};

export const validateRoomAccess = async (req, res) => {
  try {
    const { roomId } = req.params;
    const { accessToken } = req.body;

    // AUDIT: Validate accessToken type to prevent NoSQL injection
    if (accessToken && typeof accessToken !== "string") {
      return res.status(400).json({ message: "Invalid access token format" });
    }

    const room = await Room.findOne({ roomId, isActive: true });

    if (!room) {
      return res.status(404).json({ message: "Room not found" });
    }

    // AUDIT: Use timing-safe comparison to prevent timing-based oracle attacks on room tokens
    if (!room.isPublic) {
      const expected = Buffer.from(room.accessToken);
      const received = Buffer.from(String(accessToken || ""));
      if (expected.length !== received.length ||
          !crypto.timingSafeEqual(expected, received)) {
        return res.status(403).json({ message: "Invalid access token" });
      }
    }

    if (room.currentParticipants >= room.maxParticipants) {
      return res.status(403).json({ message: "Room is full" });
    }

    res.status(200).json({
      success: true,
      message: "Access granted",
      room: {
        id: room._id,
        roomId: room.roomId,
        name: room.name,
        maxParticipants: room.maxParticipants,
        currentParticipants: room.currentParticipants,
      },
    });
  } catch (error) {
    logger.error("Validate room access error", { error: error.message });
    // AUDIT: Never expose internal error details
    res.status(500).json({ message: "Error validating access" });
  }
};

export const getCompletedRooms = async (req, res) => {
  try {
    // AUDIT: Clamp pagination params to prevent resource exhaustion
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 10), 100);

    // Get only completed rooms (closed and inactive) created by the user
    const query = {
      isActive: false,
      closedAt: { $ne: null },
      createdBy: req.user.id,
    };

    const rooms = await Room.find(query)
      .populate("createdBy", "username displayName avatar")
      .sort({ closedAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit);

    const count = await Room.countDocuments(query);

    res.status(200).json({
      success: true,
      rooms: rooms.map((room) => ({
        id: room._id,
        roomId: room.roomId,
        name: room.name,
        description: room.description,
        isPublic: room.isPublic,
        maxParticipants: room.maxParticipants,
        currentParticipants: room.currentParticipants,
        createdBy: room.createdBy,
        createdAt: room.createdAt,
        closedAt: room.closedAt,
      })),
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(count / limit),
        totalRooms: count,
      },
    });
  } catch (error) {
    logger.error("Get completed rooms error", { error: error.message });
    // AUDIT: Never expose internal error details
    res.status(500).json({ message: "Error fetching completed rooms" });
  }
};

export const deleteRoom = async (req, res) => {
  try {
    const { roomId } = req.params;

    const room = await Room.findOne({ roomId });

    if (!room) {
      return res.status(404).json({ message: "Room not found" });
    }

    if (room.createdBy.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this room" });
    }

    // Only allow deletion of completed rooms (closed and inactive)
    if (room.isActive || !room.closedAt) {
      return res.status(400).json({
        message:
          "Can only delete completed rooms. Please close the room first.",
      });
    }

    // Permanently delete the room
    await Room.deleteOne({ roomId });

    logger.info("Room permanently deleted", { roomId, deletedBy: req.user.id });

    res.status(200).json({
      success: true,
      message: "Room deleted successfully",
    });
  } catch (error) {
    logger.error("Delete room error", { error: error.message });
    // AUDIT: Never expose internal error details
    res.status(500).json({ message: "Error deleting room" });
  }
};
