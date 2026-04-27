import express from "express";
import { protect } from "../middleware/auth.js";
import { requireAdmin } from "../middleware/adminAuth.js"; // AUDIT: Import admin auth
import {
  getSessions,
  getActiveSessions,
  getSessionById,
  getSessionsByRoom,
  getUserSessions,
  getSessionStats,
} from "../controllers/sessionController.js";

const router = express.Router();

// All session routes require authentication
router.use(protect);

// AUDIT: Restrict system-wide session listing to admins only
router.get("/", requireAdmin, getSessions);
router.get("/active", requireAdmin, getActiveSessions);
router.get("/stats", requireAdmin, getSessionStats);

// Get current user's sessions — safe for any authenticated user
router.get("/me", getUserSessions);

// Get sessions by room
router.get("/room/:roomId", getSessionsByRoom);

// Get session by ID
router.get("/:sessionId", getSessionById);

export default router;
