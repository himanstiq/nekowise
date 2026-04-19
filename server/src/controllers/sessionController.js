import Session from "../models/Session.js";
import Room from "../models/Room.js";
import logger from "../utils/logger.js";

// Get all sessions (paginated)
export const getSessions = async (req, res) => {
  try {
    // AUDIT: Clamp pagination params to prevent resource exhaustion
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);
    const skip = (page - 1) * limit;

    const sessions = await Session.find()
      .sort({ startedAt: -1 })
      .skip(skip)
      .limit(limit)
      .select("-participants");

    const total = await Session.countDocuments();

    res.json({
      sessions,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    logger.error("Get sessions error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch sessions" });
  }
};

// Get active sessions
export const getActiveSessions = async (req, res) => {
  try {
    const sessions = await Session.find({ isActive: true })
      .sort({ startedAt: -1 })
      .select("-participants");

    res.json({ sessions, count: sessions.length });
  } catch (error) {
    logger.error("Get active sessions error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch active sessions" });
  }
};

// Get session by ID
export const getSessionById = async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await Session.findOne({ sessionId });

    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    res.json({ session });
  } catch (error) {
    logger.error("Get session by ID error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch session" });
  }
};

// Get sessions for a specific room
export const getSessionsByRoom = async (req, res) => {
  try {
    const { roomId } = req.params;

    const sessions = await Session.find({ roomId })
      .sort({ startedAt: -1 })
      .limit(50);

    res.json({ sessions, count: sessions.length });
  } catch (error) {
    logger.error("Get sessions by room error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch room sessions" });
  }
};

// Get sessions for current user
export const getUserSessions = async (req, res) => {
  try {
    const userId = req.user.id;

    const sessions = await Session.find({
      "participants.userId": userId,
    })
      .sort({ startedAt: -1 })
      .limit(50)
      .select("-participants");

    res.json({ sessions, count: sessions.length });
  } catch (error) {
    logger.error("Get user sessions error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch user sessions" });
  }
};

// Get session statistics
export const getSessionStats = async (req, res) => {
  try {
    const totalSessions = await Session.countDocuments();
    const activeSessions = await Session.countDocuments({ isActive: true });

    const avgDuration = await Session.aggregate([
      { $match: { isActive: false, totalDuration: { $gt: 0 } } },
      { $group: { _id: null, avgDuration: { $avg: "$totalDuration" } } },
    ]);

    const avgParticipants = await Session.aggregate([
      { $match: { isActive: false } },
      { $group: { _id: null, avgParticipants: { $avg: "$avgParticipants" } } },
    ]);

    const totalMessages = await Session.aggregate([
      {
        $group: { _id: null, totalMessages: { $sum: "$stats.totalMessages" } },
      },
    ]);

    res.json({
      stats: {
        totalSessions,
        activeSessions,
        avgDuration: Math.round(avgDuration[0]?.avgDuration || 0),
        avgParticipants: Math.round(avgParticipants[0]?.avgParticipants || 0),
        totalMessages: totalMessages[0]?.totalMessages || 0,
      },
    });
  } catch (error) {
    logger.error("Get session stats error", { error: error.message });
    res.status(500).json({ message: "Failed to fetch session statistics" });
  }
};
