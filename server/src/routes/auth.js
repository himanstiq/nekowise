import express from "express";
import {
  register,
  login,
  getMe,
  refreshToken,
  generateWsTicket,
  logout,
} from "../controllers/authController.js";
import { protect } from "../middleware/auth.js";
import { authLimiter } from "../middleware/rateLimiter.js";

const router = express.Router();

// Apply strict rate limiting to auth endpoints
router.post("/register", authLimiter, register);
router.post("/login", authLimiter, login);
router.post("/refresh", authLimiter, refreshToken); // SEC-010: rate-limited now
router.get("/me", protect, getMe);

// SEC-001: Short-lived WebSocket ticket endpoint (requires auth cookie)
router.post("/ws-ticket", protect, generateWsTicket);

// SEC-001: Server-side logout to clear httpOnly cookies
router.post("/logout", protect, logout);

export default router;
