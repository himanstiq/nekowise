import Room from "../models/Room.js";
import Session from "../models/Session.js";
import User from "../models/User.js";
import logger from "../utils/logger.js";
import os from "os";

// Get system statistics
export const getSystemStats = async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ isActive: true });
    const totalRooms = await Room.countDocuments();
    const activeRooms = await Room.countDocuments({ isActive: true });
    const activeSessions = await Session.countDocuments({ isActive: true });
    const totalSessions = await Session.countDocuments();

    // System metrics
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    res.json({
      stats: {
        users: {
          total: totalUsers,
          active: activeUsers,
        },
        rooms: {
          total: totalRooms,
          active: activeRooms,
        },
        sessions: {
          total: totalSessions,
          active: activeSessions,
        },
        system: {
          uptime: Math.floor(uptime),
          memory: {
            heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
            heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
            rss: Math.round(memoryUsage.rss / 1024 / 1024),
          },
          cpu: {
            user: cpuUsage.user,
            system: cpuUsage.system,
          },
          platform: os.platform(),
          nodeVersion: process.version,
        },
      },
    });
  } catch (error) {
    logger.error("Get system stats error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch system statistics" });
  }
};

// Get active rooms with details
export const getActiveRooms = async (req, res) => {
  try {
    // AUDIT: Add pagination to prevent unbounded result sets at scale
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 50), 200);
    const page = Math.max(1, parseInt(req.query.page) || 1);

    const rooms = await Room.find({ isActive: true })
      .populate("createdBy", "username email")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const count = await Room.countDocuments({ isActive: true });

    res.json({ rooms, count, pagination: { page, limit, total: count } });
  } catch (error) {
    logger.error("Get active rooms error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch active rooms" });
  }
};

// Get recent sessions
export const getRecentSessions = async (req, res) => {
  try {
    // AUDIT: Clamp limit to prevent resource exhaustion
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);

    const sessions = await Session.find()
      .sort({ startedAt: -1 })
      .limit(limit)
      .select("-participants");

    res.json({ sessions, count: sessions.length });
  } catch (error) {
    logger.error("Get recent sessions error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch recent sessions" });
  }
};

// Get all users
export const getAllUsers = async (req, res) => {
  try {
    // AUDIT: Clamp pagination params to prevent resource exhaustion
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);
    const skip = (page - 1) * limit;

    const users = await User.find()
      .select("-password")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments();

    res.json({
      users,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logger.error("Get all users error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch users" });
  }
};

// Close a room (admin only)
export const closeRoom = async (req, res) => {
  try {
    const { roomId } = req.params;

    const room = await Room.findOne({ roomId });

    if (!room) {
      return res.status(404).json({ message: "Room not found" });
    }

    room.isActive = false;
    room.closedAt = new Date();
    await room.save();

    // End the session if exists
    const session = await Session.findOne({ roomId, isActive: true });
    if (session) {
      session.endSession();
      await session.save();
    }

    logger.info("Room closed by admin", {
      roomId,
      adminId: req.user.id,
    });

    res.json({ message: "Room closed successfully", room });
  } catch (error) {
    logger.error("Close room error", { error: error.message });
    res.status(500).json({ message: "Failed to close room" });
  }
};

// Update user role
export const updateUserRole = async (req, res) => {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    if (!["user", "admin"].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Prevent removing last admin
    if (user.role === "admin" && role === "user") {
      const adminCount = await User.countDocuments({ role: "admin" });
      if (adminCount <= 1) {
        return res.status(400).json({ message: "Cannot remove last admin" });
      }
    }

    user.role = role;
    await user.save();

    logger.info("User role updated by admin", {
      userId,
      newRole: role,
      adminId: req.user.id,
    });

    res.json({
      message: "User role updated successfully",
      user: { ...user.toObject(), password: undefined },
    });
  } catch (error) {
    logger.error("Update user role error", { error: error.message });
    res.status(500).json({ message: "Failed to update user role" });
  }
};

// Delete user (admin only)
export const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Prevent deleting last admin
    if (user.role === "admin") {
      const adminCount = await User.countDocuments({ role: "admin" });
      if (adminCount <= 1) {
        return res.status(400).json({ message: "Cannot delete last admin" });
      }
    }

    // Prevent self-deletion
    if (user._id.toString() === req.user.id) {
      return res
        .status(400)
        .json({ message: "Cannot delete your own account" });
    }

    await User.findByIdAndDelete(userId);

    logger.info("User deleted by admin", {
      userId,
      adminId: req.user.id,
    });

    res.json({ message: "User deleted successfully" });
  } catch (error) {
    logger.error("Delete user error", { error: error.message });
    res.status(500).json({ message: "Failed to delete user" });
  }
};
