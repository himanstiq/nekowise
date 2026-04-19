import "dotenv/config";
import express from "express";
import { createServer } from "http";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser"; // SEC-001: Required to read httpOnly cookies
import crypto from "crypto"; // API-001: For request IDs

import connectDatabase from "./config/database.js";
import validateEnv from "./utils/validateEnv.js";
import logger from "./utils/logger.js";
import SignalingServer from "./websocket/server.js";

// Route imports
import authRoutes from "./routes/auth.js";
import roomRoutes from "./routes/room.js";
import adminRoutes from "./routes/admin.js";
import sessionRoutes from "./routes/session.js";
import healthRoutes from "./routes/health.js";

// Middleware imports
import { apiLimiter } from "./middleware/rateLimiter.js";

// DATA-001: Import Room model for startup reset
import Room from "./models/Room.js";

// Validate environment variables
validateEnv();

const PORT = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL;
const app = express();
const httpServer = createServer(app);

// SEC-008: Fail in production if CLIENT_URL is missing
if (!clientUrl && process.env.NODE_ENV === "production") {
  logger.error("CLIENT_URL is required in production");
  process.exit(1);
}

// Security middleware
app.use(helmet());
app.use(
  cors({
    origin:
      clientUrl ||
      (process.env.NODE_ENV !== "production"
        ? "http://localhost:5173"
        : false), // SEC-008: No silent fallback in production
    credentials: true, // SEC-001: Required for httpOnly cookies
  })
);
app.use(cookieParser()); // SEC-001: Parse httpOnly cookies on every request

// SEC-005: Enforce explicit body size limits to prevent memory exhaustion DoS
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Request logging
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// API-001: Structured request logging for all environments (audit trail)
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader("X-Request-ID", req.requestId);

  const start = Date.now();
  res.on("finish", () => {
    logger.info("HTTP Request", {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: Date.now() - start,
    });
  });

  next();
});

// Rate limiting
app.use("/api", apiLimiter);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/rooms", roomRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/sessions", sessionRoutes);
app.use("/api", healthRoutes);

// Global error handler
app.use((err, req, res, next) => {
  logger.error("Unhandled error", {
    error: err.message,
    stack: err.stack,
    requestId: req.requestId,
  });
  res.status(err.status || 500).json({
    message:
      process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err.message,
  });
});

// Async startup to allow DB connection and room reset before serving
(async () => {
  try {
    await connectDatabase();

    // DATA-001: Reset stale participant counts on server startup
    // After a restart, in-memory state is lost but DB may still show active participants
    const resetResult = await Room.updateMany(
      { isActive: true },
      { $set: { currentParticipants: 0 } }
    );
    if (resetResult.modifiedCount > 0) {
      logger.info("DATA-001: Reset active room participant counts on startup", {
        roomsReset: resetResult.modifiedCount,
      });
    }

    const signalingServer = new SignalingServer(httpServer);

    httpServer.listen(PORT, () => {
      logger.info(`Server running on port ${PORT}`);
      logger.info(`WebSocket server running on path /ws`);
      logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
    });

    const gracefulShutdown = (signal) => {
      logger.info(`${signal} received, shutting down gracefully`);

      // MEM-001: Clean up server intervals
      signalingServer.destroy();

      signalingServer.wss.clients.forEach((ws) => {
        ws.close(1000, "Server shutting down");
      });

      httpServer.close(() => {
        logger.info("Server closed");
        process.exit(0);
      });

      setTimeout(() => {
        logger.error("Forcing shutdown after timeout");
        process.exit(1);
      }, 10000);
    };

    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));
  } catch (error) {
    logger.error("Failed to start server", { error: error.message });
    process.exit(1);
  }
})();

export default app;
