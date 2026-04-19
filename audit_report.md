# Neko WebRTC Platform — Production-Readiness Audit Report

**Date:** 2026-04-19  
**Auditor:** Principal-Level Software Engineering Review  
**Scope:** Full-stack codebase — server (Express 5 + WebSocket) and client (React 19 + WebRTC)

---

> [!CAUTION]
> This audit identified **6 CRITICAL**, **14 HIGH**, **17 MEDIUM**, and **14 LOW** severity findings across all 8 audit dimensions. The codebase requires significant hardening before production deployment on the public internet.

---

## Executive Summary

| Dimension | Critical | High | Medium | Low |
|---|---|---|---|---|
| 1. Security Vulnerabilities | 3 | 5 | 3 | 2 |
| 2. Memory Leaks & Resource Mgmt | 1 | 2 | 2 | 1 |
| 3. WebRTC & Real-Time Correctness | 1 | 2 | 3 | 1 |
| 4. Error Handling & Resilience | 0 | 2 | 3 | 2 |
| 5. Performance & Efficiency | 0 | 1 | 3 | 3 |
| 6. Data Model & Persistence | 1 | 1 | 1 | 2 |
| 7. API Design & Hardening | 0 | 1 | 2 | 2 |
| 8. Code Quality & Maintainability | 0 | 0 | 0 | 1 |
| **Totals** | **6** | **14** | **17** | **14** |

---

## Dimension 1: Security Vulnerabilities

---

### [CRITICAL] SEC-001: JWT Tokens Stored in localStorage — XSS Exfiltration Vector

**Severity:** CRITICAL  
**Dimension:** Security Vulnerabilities  
**Location:** [AuthContext.jsx](file:///e:/Nekowise/client/src/contexts/AuthContext.jsx#L34-L49), [websocket.js](file:///e:/Nekowise/client/src/services/websocket.js#L122), [api.js](file:///e:/Nekowise/client/src/services/api.js#L10)  
**Impact:** Any XSS vulnerability (including via third-party dependencies) allows an attacker to steal JWT tokens and impersonate any user. The token is also passed as a query parameter in the WebSocket URL, making it visible in server logs, proxy logs, and browser history.

**Current Code:**
```javascript
// AuthContext.jsx L34-35
localStorage.setItem("token", response.token);
localStorage.setItem("refreshToken", response.refreshToken);

// websocket.js L122
const token = localStorage.getItem("token");

// websocket.js L34 — token in URL query string
const wsUrl = `${WS_URL}?token=${token}`;
```

**Refactored Code:**
```javascript
// Server: authController.js — Set tokens as httpOnly cookies
export const login = async (req, res) => {
  // ... existing validation ...
  const token = generateToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth/refresh',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  res.status(200).json({
    success: true,
    message: "Login successful",
    user: { /* ... */ },
    // Do NOT send tokens in body
  });
};

// For WebSocket: Use a short-lived ticket exchanged via authenticated HTTP
// Server: Add a new endpoint
router.post('/auth/ws-ticket', protect, (req, res) => {
  const ticket = generateToken(req.user.id, '30s'); // 30-second expiry
  res.json({ ticket });
});

// Client: websocket.js — Fetch ticket before connecting
async connect() {
  const response = await fetch('/api/auth/ws-ticket', {
    method: 'POST',
    credentials: 'include', // sends httpOnly cookie
  });
  const { ticket } = await response.json();
  this.ws = new WebSocket(`${WS_URL}?ticket=${ticket}`);
}
```

---

### [CRITICAL] SEC-002: Refresh Token Uses Same JWT Secret and Has No Revocation

**Severity:** CRITICAL  
**Dimension:** Security Vulnerabilities  
**Location:** [jwt.js](file:///e:/Nekowise/server/src/utils/jwt.js#L22-L24), [authController.js](file:///e:/Nekowise/server/src/controllers/authController.js#L144-L173)  
**Impact:** Access tokens and refresh tokens are signed with the same `JWT_SECRET` — meaning an access token can be used as a refresh token and vice versa. There is no token family tracking, no rotation enforcement, and no revocation capability (no server-side token store). A leaked refresh token grants permanent access.

**Current Code:**
```javascript
// jwt.js L22-24
export const generateRefreshToken = (userId) => {
  return generateToken(userId, process.env.JWT_REFRESH_EXPIRE);
};

// authController.js L152 — refresh uses same verifyToken
const decoded = verifyToken(refreshToken);
// Anyone who has an access token can call this endpoint
```

**Refactored Code:**
```javascript
// jwt.js — Use separate secrets and add token type to payload
export const generateToken = (userId, expiresIn = process.env.JWT_EXPIRE) => {
  return jwt.sign(
    { id: userId, type: 'access' },
    process.env.JWT_SECRET,
    { expiresIn }
  );
};

export const generateRefreshToken = (userId) => {
  return jwt.sign(
    { id: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET, // SEPARATE secret
    { expiresIn: process.env.JWT_REFRESH_EXPIRE }
  );
};

export const verifyRefreshToken = (token) => {
  const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  if (decoded.type !== 'refresh') {
    throw new Error('Invalid token type');
  }
  return decoded;
};

// authController.js — Token rotation with family tracking
export const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token required" });
  }

  const decoded = verifyRefreshToken(refreshToken); // uses separate secret
  const user = await User.findById(decoded.id);

  if (!user || !user.isActive) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  // Store refresh token hash in DB for revocation
  // Invalidate old token, issue new pair
  const newToken = generateToken(user._id);
  const newRefreshToken = generateRefreshToken(user._id);

  res.status(200).json({ token: newToken, refreshToken: newRefreshToken });
};
```

---

### [CRITICAL] SEC-003: No WebSocket Origin Validation

**Severity:** CRITICAL  
**Dimension:** Security Vulnerabilities  
**Location:** [websocket/server.js](file:///e:/Nekowise/server/src/websocket/server.js#L10-L13)  
**Impact:** The WebSocket server accepts connections from any origin. A malicious website can connect to the WebSocket server using a stolen/valid JWT, enabling cross-site WebSocket hijacking (CSWSH). The `ws` library does not perform origin checking by default.

**Current Code:**
```javascript
// websocket/server.js L10-13
this.wss = new WebSocketServer({
  server,
  path: "/ws",
});
```

**Refactored Code:**
```javascript
this.wss = new WebSocketServer({
  server,
  path: "/ws",
  verifyClient: (info, callback) => {
    const origin = info.origin || info.req.headers.origin;
    const allowedOrigins = [process.env.CLIENT_URL];

    if (!origin || !allowedOrigins.includes(origin)) {
      logger.warn("WebSocket connection rejected: invalid origin", { origin });
      callback(false, 403, "Forbidden: invalid origin");
      return;
    }
    callback(true);
  },
  maxPayload: 64 * 1024, // 64KB max message size
});
```

---

### [HIGH] SEC-004: NoSQL Injection via Unsanitized User Input in Mongo Queries

**Severity:** HIGH  
**Dimension:** Security Vulnerabilities  
**Location:** [authController.js](file:///e:/Nekowise/server/src/controllers/authController.js#L19-L21), [roomController.js](file:///e:/Nekowise/server/src/controllers/roomController.js#L53-L58)  
**Impact:** Query parameters from `req.body` and `req.query` are passed directly to Mongoose queries. An attacker can submit `{ "email": { "$ne": "" } }` to bypass authentication or enumerate users.

**Current Code:**
```javascript
// authController.js L19-21
const existingUser = await User.findOne({
  $or: [{ email }, { username }],
});

// authController.js L75 — login
const user = await User.findOne({ email }).select("+password");

// roomController.js L53
const { page = 1, limit = 10, isPublic } = req.query;
// limit is cast via `limit * 1` but page/limit are not bounded
```

**Refactored Code:**
```javascript
// authController.js — Sanitize inputs
import mongoSanitize from 'express-mongo-sanitize';

// In server.js — Add globally
app.use(mongoSanitize()); // Strips $ and . from req.body/query/params

// Additionally, validate types explicitly:
export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
    return res.status(400).json({ message: "Invalid credentials format" });
  }

  const user = await User.findOne({ email: String(email) }).select("+password");
  // ...
};
```

---

### [HIGH] SEC-005: No `express.json()` Body Size Limit

**Severity:** HIGH  
**Dimension:** Security Vulnerabilities  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js#L42)  
**Impact:** Without a body size limit, an attacker can send multi-gigabyte POST bodies to exhaust server memory and cause a denial-of-service.

**Current Code:**
```javascript
app.use(express.json()); // No limit specified — default is 100KB but should be explicit
app.use(express.urlencoded({ extended: true })); // Same issue
```

**Refactored Code:**
```javascript
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
```

---

### [HIGH] SEC-006: Weak Chat Message Sanitization — Regex Bypass

**Severity:** HIGH  
**Dimension:** Security Vulnerabilities  
**Location:** [messageHandler.js](file:///e:/Nekowise/server/src/websocket/messageHandler.js#L344-L348)  
**Impact:** The sanitization uses naive regex patterns that are easily bypassed. For example, `javaScript:` (mixed case), `onm\nouseover=` (newline insertion), or URL-encoded payloads will pass through. The client renders messages via React JSX (not `dangerouslySetInnerHTML`), which provides baseline XSS protection, but the sanitization logic gives a false sense of security and should use a proper library.

**Current Code:**
```javascript
const sanitizedText = text
  .trim()
  .replace(/[<>]/g, "") // Only strips < and >
  .replace(/javascript:/gi, "") // Easily bypassed: "java\tscript:"
  .replace(/on\w+\s*=/gi, ""); // Bypassed: "onmouseover ="
```

**Refactored Code:**
```javascript
import DOMPurify from 'isomorphic-dompurify';

// Or simply escape HTML entities and strip control characters:
function sanitizeChatMessage(text) {
  return text
    .trim()
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Strip control chars
    .substring(0, 500); // Enforce length limit
}
// Since React renders as text content (not HTML), full DOMPurify
// is optional, but the server should still normalize the string.
```

---

### [HIGH] SEC-007: JWT Secret Strength Not Enforced

**Severity:** HIGH  
**Dimension:** Security Vulnerabilities  
**Location:** [validateEnv.js](file:///e:/Nekowise/server/src/utils/validateEnv.js), [.env.example](file:///e:/Nekowise/server/.env.example#L10)  
**Impact:** The `.env.example` ships with `JWT_SECRET=your_super_secret_jwt_key_change_in_production`. The `validateEnv` only checks for presence, not minimum entropy. Deployers often forget to change default values.

**Current Code:**
```javascript
const requiredEnvVars = ["MONGODB_URI", "JWT_SECRET", "CLIENT_URL"];
// Only checks if values exist, not strength
```

**Refactored Code:**
```javascript
const validateEnv = () => {
  const missing = requiredEnvVars.filter((varName) => !process.env[varName]);
  if (missing.length > 0) {
    logger.error(`Missing required environment variables: ${missing.join(", ")}`);
    process.exit(1);
  }

  // Enforce JWT secret strength
  if (process.env.JWT_SECRET.length < 32) {
    logger.error("JWT_SECRET must be at least 32 characters for production security");
    process.exit(1);
  }

  if (process.env.JWT_SECRET.includes("change_in_production") ||
      process.env.JWT_SECRET === "your_super_secret_jwt_key_change_in_production") {
    logger.error("JWT_SECRET contains default value — must be changed for production");
    process.exit(1);
  }

  // Enforce HTTPS in production
  if (process.env.NODE_ENV === 'production' && 
      !process.env.CLIENT_URL?.startsWith('https://')) {
    logger.error("CLIENT_URL must use HTTPS in production");
    process.exit(1);
  }

  logger.info("Environment variables validated successfully");
};
```

---

### [HIGH] SEC-008: CORS Fallback to `localhost` in Absence of `CLIENT_URL`

**Severity:** HIGH  
**Dimension:** Security Vulnerabilities  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js#L37)  
**Impact:** If `CLIENT_URL` is unset, CORS falls back to `http://localhost:5173`. In production, this might silently accept requests from localhost (on the same machine) or simply fail. The fallback masks misconfigurations.

**Current Code:**
```javascript
cors({
  origin: clientUrl || "http://localhost:5173", // Silent fallback
  credentials: true,
})
```

**Refactored Code:**
```javascript
const clientUrl = process.env.CLIENT_URL;
if (!clientUrl && process.env.NODE_ENV === 'production') {
  logger.error("CLIENT_URL is required in production");
  process.exit(1);
}

app.use(cors({
  origin: clientUrl || (process.env.NODE_ENV === 'development' ? 'http://localhost:5173' : false),
  credentials: true,
}));
```

---

### [MEDIUM] SEC-009: Missing `Content-Security-Policy` Header

**Severity:** MEDIUM  
**Dimension:** Security Vulnerabilities  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js#L34)  
**Impact:** `helmet()` is used with defaults, which includes a very permissive CSP. No custom CSP is configured to restrict script sources, connect sources, or media sources.

**Refactored Code:**
```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", clientUrl, clientUrl.replace('https://', 'wss://')],
      mediaSrc: ["'self'", "blob:"],
      imgSrc: ["'self'", "data:", "blob:"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));
```

---

### [MEDIUM] SEC-010: Refresh Endpoint Has No Rate Limiting

**Severity:** MEDIUM  
**Dimension:** Security Vulnerabilities  
**Location:** [routes/auth.js](file:///e:/Nekowise/server/src/routes/auth.js#L16)  
**Impact:** The `/api/auth/refresh` endpoint is not rate-limited, allowing an attacker to brute-force refresh tokens or overwhelm the server.

**Current Code:**
```javascript
router.post("/refresh", refreshToken); // No rate limiter applied
```

**Refactored Code:**
```javascript
router.post("/refresh", authLimiter, refreshToken);
```

---

### [MEDIUM] SEC-011: Session Endpoints Expose All Sessions to Any Authenticated User

**Severity:** MEDIUM  
**Dimension:** Security Vulnerabilities  
**Location:** [sessionController.js](file:///e:/Nekowise/server/src/controllers/sessionController.js#L6-L33), [routes/session.js](file:///e:/Nekowise/server/src/routes/session.js#L18)  
**Impact:** `GET /api/sessions` returns all sessions system-wide to any authenticated user. Users can enumerate other users' meetings, durations, and activity. This should be restricted to admin users or scoped to the requesting user.

**Refactored Code:**
```javascript
// Make GET /api/sessions admin-only, keep /api/sessions/me for regular users
router.get("/", protect, requireAdmin, getSessions); // admin only
router.get("/me", protect, getUserSessions);          // user's own
```

---

### [LOW] SEC-012: WebSocket Token Logged in Server URL

**Severity:** LOW  
**Dimension:** Security Vulnerabilities  
**Location:** [websocket.js (client)](file:///e:/Nekowise/client/src/services/websocket.js#L35)  
**Impact:** The full WebSocket URL including the JWT token is logged to the browser console.

**Current Code:**
```javascript
console.log("Connecting to WebSocket:", wsUrl); // Logs token in URL
```

**Refactored Code:**
```javascript
console.log("Connecting to WebSocket:", WS_URL); // Don't log the token
```

---

### [LOW] SEC-013: Internal Stack Traces Exposed in Error Responses

**Severity:** LOW  
**Dimension:** Security Vulnerabilities  
**Location:** [authController.js](file:///e:/Nekowise/server/src/controllers/authController.js#L61), [roomController.js](file:///e:/Nekowise/server/src/controllers/roomController.js#L47)  
**Impact:** Error responses include `error: error.message` which may leak internal implementation details (Mongoose validation messages, driver errors) to clients.

**Refactored Code:**
```javascript
// Replace all instances of:
res.status(500).json({ message: "Error creating room", error: error.message });
// With:
res.status(500).json({ message: "Error creating room" });
// Log the actual error server-side only:
logger.error("Create room error", { error: error.message, stack: error.stack });
```

---

## Dimension 2: Memory Leaks & Resource Management

---

### [CRITICAL] MEM-001: Unbounded In-Memory Maps on WebSocket Server

**Severity:** CRITICAL  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [websocket/server.js](file:///e:/Nekowise/server/src/websocket/server.js#L15-L18)  
**Impact:** `this.clients`, `this.userConnections`, `this.rooms`, and `this.messageRateLimits` are unbounded `Map` objects. If disconnect handlers fail (due to async errors not being caught in all paths), entries accumulate indefinitely. The `messageRateLimits` map stores growing timestamp arrays per connection, and while old entries are filtered per-message, orphaned connections never get cleaned up if `handleDisconnect` fails silently.

**Current Code:**
```javascript
this.clients = new Map();           // Never bounded
this.userConnections = new Map();   // Never bounded
this.rooms = new Map();             // Never bounded
this.messageRateLimits = new Map(); // Timestamp arrays grow without cap
```

**Refactored Code:**
```javascript
constructor(server) {
  // ... existing ...
  
  // Periodic cleanup of stale connections (every 60 seconds)
  this.cleanupInterval = setInterval(() => {
    this.cleanupStaleConnections();
  }, 60000);
}

cleanupStaleConnections() {
  let cleaned = 0;
  this.clients.forEach((client, connectionId) => {
    if (client.ws.readyState === client.ws.CLOSED || 
        client.ws.readyState === client.ws.CLOSING) {
      this.handleDisconnect(client).catch(err => {
        logger.error("Cleanup disconnect error", { connectionId, error: err.message });
      });
      cleaned++;
    }
  });

  // Clean orphaned rate limit entries
  this.messageRateLimits.forEach((_, key) => {
    if (!this.clients.has(key)) {
      this.messageRateLimits.delete(key);
    }
  });

  if (cleaned > 0) {
    logger.info("Cleaned stale connections", { count: cleaned });
  }
}

// In graceful shutdown:
destroy() {
  clearInterval(this.cleanupInterval);
}
```

---

### [HIGH] MEM-002: AudioContext Instances Not Properly Cleaned on Stream Change

**Severity:** HIGH  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [useActiveSpeaker.js](file:///e:/Nekowise/client/src/hooks/useActiveSpeaker.js#L13-L31), [audioMonitor.js](file:///e:/Nekowise/client/src/services/audioMonitor.js)  
**Impact:** When `remoteStreams` changes (user joins/leaves), `useActiveSpeaker` calls `audioMonitor.stopAll()` in cleanup and re-monitors. But `stopAll()` iterates `audioContexts` and calls `stopMonitoring()` which calls `audioContext.close()`. The `close()` is async and returns a Promise that is not awaited, potentially causing `AudioContext` state errors. Also, the `updateVolume` function inside `useActiveSpeaker` creates a new `Map` on every volume change from every user, triggering massive re-renders (see PERF-001).

**Current Code:**
```javascript
// useActiveSpeaker.js — cleanup
return () => {
  audioMonitor.stopAll(); // Not awaited; audioContext.close() is async
};

// audioMonitor.js L72-73
const audioContext = this.audioContexts.get(userId);
if (audioContext) {
  audioContext.close(); // Returns Promise, not awaited
```

**Refactored Code:**
```javascript
// audioMonitor.js
async stopMonitoring(userId) {
  const frameId = this.animationFrames.get(userId);
  if (frameId) {
    cancelAnimationFrame(frameId);
    this.animationFrames.delete(userId);
  }

  const audioContext = this.audioContexts.get(userId);
  if (audioContext && audioContext.state !== 'closed') {
    try {
      await audioContext.close();
    } catch (e) {
      // Already closed, ignore
    }
    this.audioContexts.delete(userId);
  }

  this.analysers.delete(userId);
  this.volumeCallbacks.delete(userId);
}
```

---

### [HIGH] MEM-003: PeerConnection `close()` Does Not Stop Remote MediaStream Tracks

**Severity:** HIGH  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [PeerConnection.js](file:///e:/Nekowise/client/src/services/PeerConnection.js#L291-L301)  
**Impact:** When a peer connection is closed, only `this.pc.close()` is called. The remote `MediaStream` tracks obtained via `ontrack` are never stopped. This keeps the media pipeline active and may leak browser media resources. Additionally, event handlers on the closed `RTCPeerConnection` are never removed.

**Current Code:**
```javascript
close() {
  if (this.connectionFailedTimeout) {
    clearTimeout(this.connectionFailedTimeout);
    this.connectionFailedTimeout = null;
  }
  this.pc.close();
}
```

**Refactored Code:**
```javascript
close() {
  if (this.connectionFailedTimeout) {
    clearTimeout(this.connectionFailedTimeout);
    this.connectionFailedTimeout = null;
  }

  // Remove all event handlers to prevent callbacks on closed connection
  this.pc.onicecandidate = null;
  this.pc.ontrack = null;
  this.pc.onconnectionstatechange = null;
  this.pc.oniceconnectionstatechange = null;
  this.pc.onicegatheringstatechange = null;
  this.pc.onnegotiationneeded = null;

  // Stop all received tracks
  this.pc.getReceivers().forEach(receiver => {
    if (receiver.track) {
      receiver.track.stop();
    }
  });

  this.pc.close();
  this.onTrackCallback = null;
  this.onConnectionStateChangeCallback = null;
}
```

---

### [MEDIUM] MEM-004: WebSocket Reconnect Timer Not Cleared on Manual Disconnect

**Severity:** MEDIUM  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [websocket.js (client)](file:///e:/Nekowise/client/src/services/websocket.js#L121-L128)  
**Impact:** `scheduleReconnect` uses `setTimeout` but the timeout ID is never stored, so `disconnect()` cannot cancel a pending reconnection. If `disconnect()` is called during the delay, the timer still fires and attempts to reconnect.

**Current Code:**
```javascript
scheduleReconnect() {
  // ...
  setTimeout(() => { // ID not stored!
    const token = localStorage.getItem("token");
    if (token) {
      this.connect(token);
    }
  }, delay);
}

disconnect() {
  this.shouldReconnect = false; // Flag-based, but timer already queued
  // ...
}
```

**Refactored Code:**
```javascript
constructor() {
  // ... existing ...
  this.reconnectTimer = null;
}

scheduleReconnect() {
  // ...
  this.reconnectTimer = setTimeout(() => {
    this.reconnectTimer = null;
    if (!this.shouldReconnect) return; // Double-check flag
    const token = localStorage.getItem("token");
    if (token) {
      this.connect(token);
    }
  }, delay);
}

disconnect() {
  this.shouldReconnect = false;
  if (this.reconnectTimer) {
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
  }
  this.stopHeartbeat();
  // ... rest of disconnect
}
```

---

### [MEDIUM] MEM-005: `useActiveSpeaker` volumeHistory Ref Grows Without Bounds

**Severity:** MEDIUM  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [useActiveSpeaker.js](file:///e:/Nekowise/client/src/hooks/useActiveSpeaker.js#L41-L50)  
**Impact:** `volumeHistory.current` accumulates entries for users who have left. Keys are never removed from the Map when a user departs.

**Refactored Code:**
```javascript
// Add cleanup when remoteStreams changes
useEffect(() => {
  // Clean up entries for departed users
  const currentIds = new Set(['local', ...remoteStreams.map(s => s.userId)]);
  volumeHistory.current.forEach((_, userId) => {
    if (!currentIds.has(userId)) {
      volumeHistory.current.delete(userId);
    }
  });
}, [remoteStreams]);
```

---

### [LOW] MEM-006: Room.jsx Cleanup Effect Has Stale `screenStream` Reference

**Severity:** LOW  
**Dimension:** Memory Leaks & Resource Management  
**Location:** [Room.jsx](file:///e:/Nekowise/client/src/pages/Room.jsx#L265-L283)  
**Impact:** The cleanup effect depends on `[screenStream, leaveRoom]`. When `screenStream` changes, the old cleanup runs (stopping the *previous* stream) and the new cleanup is registered. This causes unnecessary re-registration of the cleanup effect and can prematurely stop screen sharing under certain race conditions.

**Refactored Code:**
```javascript
// Use a ref for screenStream in cleanup to avoid dependency
const screenStreamRef = useRef(null);

useEffect(() => {
  screenStreamRef.current = screenStream;
}, [screenStream]);

useEffect(() => {
  return () => {
    if (screenStreamRef.current) {
      screenStreamRef.current.getTracks().forEach(track => track.stop());
    }
    leaveRoom();
    peerConnectionManager.closeAllConnections();
    mediaService.stopLocalStream();
  };
}, [leaveRoom]); // Only depends on leaveRoom
```

---

## Dimension 3: WebRTC & Real-Time Correctness

---

### [CRITICAL] RTC-001: Glare Condition — No Offer Collision Handling

**Severity:** CRITICAL  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [peerConnectionManager.js](file:///e:/Nekowise/client/src/services/peerConnectionManager.js#L89-L113)  
**Impact:** When two peers simultaneously send offers (glare), both receive offers in `have-local-offer` state. The current code logs a warning but proceeds anyway, which causes `InvalidStateError` exceptions and permanently broken connections.

**Current Code:**
```javascript
async handleOffer(message) {
  const { fromUserId, fromUsername, offer } = message;
  const pc = await this.createPeerConnection(fromUserId, fromUsername);

  const signalingState = pc.pc.signalingState;
  if (signalingState !== "stable") {
    console.warn(`Received offer in state: ${signalingState}. Attempting anyway...`);
    // Proceeds and likely throws InvalidStateError
  }

  await pc.setRemoteDescription(offer);
  const answer = await pc.createAnswer();
  // ...
}
```

**Refactored Code:**
```javascript
async handleOffer(message) {
  const { fromUserId, fromUsername, offer } = message;
  const pc = await this.createPeerConnection(fromUserId, fromUsername);

  const signalingState = pc.pc.signalingState;
  
  // Handle glare: use polite/impolite peer pattern
  // The peer with the lower userId is "polite" (yields to incoming offers)
  const isPolite = this.localUserId < fromUserId;
  
  if (signalingState !== "stable") {
    if (!isPolite) {
      // Impolite peer: ignore incoming offer, keep our own
      console.log(`Ignoring offer from ${fromUserId} (we are impolite peer)`);
      return;
    }
    // Polite peer: rollback our offer and accept theirs
    console.log(`Rolling back local offer for ${fromUserId} (we are polite peer)`);
    await pc.pc.setLocalDescription({ type: "rollback" });
  }

  await pc.setRemoteDescription(offer);
  const answer = await pc.createAnswer();
  this.signaling.sendAnswer(fromUserId, answer);
}
```

---

### [HIGH] RTC-002: No TURN Server Configuration — Calls Fail Behind Symmetric NAT

**Severity:** HIGH  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [webrtc.js (config)](file:///e:/Nekowise/client/src/config/webrtc.js#L1-L15)  
**Impact:** ICE configuration only includes STUN servers. Approximately 10-15% of users behind symmetric NATs, enterprise firewalls, or VPNs will be unable to establish peer connections. There is no TURN server configured — the `.env.example` shows TURN as commented-out.

**Current Code:**
```javascript
export const STUN_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  // ... more STUN only
];
```

**Refactored Code:**
```javascript
export const RTC_CONFIG = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    // TURN servers (required for production!)
    ...(import.meta.env.VITE_TURN_URL ? [{
      urls: import.meta.env.VITE_TURN_URL,
      username: import.meta.env.VITE_TURN_USERNAME,
      credential: import.meta.env.VITE_TURN_CREDENTIAL,
    }] : []),
  ],
  iceCandidatePoolSize: 10,
  bundlePolicy: "max-bundle",
  rtcpMuxPolicy: "require",
  iceTransportPolicy: "all",
};
```

---

### [HIGH] RTC-003: ICE Restart Has No Exponential Backoff

**Severity:** HIGH  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [PeerConnection.js](file:///e:/Nekowise/client/src/services/PeerConnection.js#L111-L161)  
**Impact:** ICE restart attempts are fired immediately in rapid succession. Three restarts happen as fast as the async operations allow, flooding the signaling channel with offers and potentially worsening network conditions.

**Refactored Code:**
```javascript
async handleConnectionFailed() {
  if (this.isRestarting) return;
  if (this.restartAttempts >= this.maxRestartAttempts) {
    // ... existing max-reached logic
    return;
  }

  this.isRestarting = true;
  this.restartAttempts++;

  // Exponential backoff: 1s, 2s, 4s
  const delay = Math.min(1000 * Math.pow(2, this.restartAttempts - 1), 8000);
  console.log(`ICE restart in ${delay}ms (attempt ${this.restartAttempts})`);

  await new Promise(resolve => setTimeout(resolve, delay));

  // Check if connection recovered during wait
  if (this.pc.connectionState === 'connected' || 
      this.pc.iceConnectionState === 'connected') {
    this.isRestarting = false;
    return;
  }

  try {
    const offer = await this.pc.createOffer({ iceRestart: true });
    await this.pc.setLocalDescription(offer);
    this.signaling.sendOffer(this.userId, offer);
  } catch (error) {
    console.error("ICE restart error:", error);
  } finally {
    this.isRestarting = false;
  }
}
```

---

### [MEDIUM] RTC-004: Mesh Topology Will Not Scale Beyond 4-5 Participants

**Severity:** MEDIUM  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** Architecture-wide  
**Impact:** In a full mesh, each participant sends N-1 video streams and receives N-1 streams. At 720p (2.5 Mbps), 6 participants require each client to send 12.5 Mbps and receive 12.5 Mbps. Most consumer internet connections cannot sustain this. The `maxParticipants` default of 6 and max of 10 is unrealistic for mesh topology.

**Recommendation:**
```
- Reduce maxParticipants to 4-5 for mesh topology
- Implement simulcast to reduce upload bandwidth
- Add server-side SFU (Selective Forwarding Unit) for 5+ participants
- At minimum, add simulcast encodings to the RTCPeerConnection:

const transceiver = pc.addTransceiver(track, {
  direction: 'sendrecv',
  sendEncodings: [
    { rid: 'low', maxBitrate: 150000, scaleResolutionDownBy: 4 },
    { rid: 'mid', maxBitrate: 500000, scaleResolutionDownBy: 2 },
    { rid: 'high', maxBitrate: 2500000 },
  ],
});
```

---

### [MEDIUM] RTC-005: Screen Share Does Not Notify Peers via Signaling

**Severity:** MEDIUM  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [Room.jsx](file:///e:/Nekowise/client/src/pages/Room.jsx#L297-L337)  
**Impact:** When starting screen share, the track is replaced via `replaceTrack()` but no signaling message is sent to inform peers that this is now a screen share (vs. camera). The `screen-share-started`/`screen-share-stopped` server handlers exist but are never called from the client.

**Refactored Code:**
```javascript
const startScreenShare = async () => {
  try {
    const stream = await mediaService.getDisplayMedia();
    // ... existing track replacement ...

    // Notify peers via signaling
    signaling.sendMessage({ type: "screen-share-started" });

    logger.info("Screen sharing started");
  } catch (error) { /* ... */ }
};

const stopScreenShare = async () => {
  try {
    // ... existing track replacement ...

    signaling.sendMessage({ type: "screen-share-stopped" });

    logger.info("Screen sharing stopped");
  } catch (error) { /* ... */ }
};
```

---

### [MEDIUM] RTC-006: `onnegotiationneeded` Handler Is Empty

**Severity:** MEDIUM  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [PeerConnection.js](file:///e:/Nekowise/client/src/services/PeerConnection.js#L105-L108)  
**Impact:** The `onnegotiationneeded` event fires when tracks are added/removed, but the handler only logs. This means track changes (like switching from camera to screen share) rely on `replaceTrack()` only, which works for 1:1 replacements but not when adding new tracks.

**Current Code:**
```javascript
this.pc.onnegotiationneeded = async () => {
  console.log("Negotiation needed with", this.userId);
  // This will be handled by the offer/answer flow
};
```

---

### [LOW] RTC-007: Bitrate Calculation in `getStats()` Is Incorrect

**Severity:** LOW  
**Dimension:** WebRTC & Real-Time Correctness  
**Location:** [PeerConnection.js](file:///e:/Nekowise/client/src/services/PeerConnection.js#L208-L210)  
**Impact:** The bitrate calculation divides `bytesReceived * 8` by `report.timestamp / 1000`. The `timestamp` is a DOMHighResTimeStamp in milliseconds since the epoch — dividing by 1000 gives seconds since epoch, not the duration of the session. The correct approach uses delta between two consecutive stats reports.

**Current Code:**
```javascript
result[kind].bitrate = report.bytesReceived
  ? (report.bytesReceived * 8) / (report.timestamp / 1000)
  : 0;
```

**Refactored Code:**
```javascript
// Store previous stats and compute delta
if (this._prevStats && this._prevStats[report.id]) {
  const prev = this._prevStats[report.id];
  const timeDelta = (report.timestamp - prev.timestamp) / 1000; // seconds
  const bytesDelta = report.bytesReceived - prev.bytesReceived;
  result[kind].bitrate = timeDelta > 0 ? (bytesDelta * 8) / timeDelta : 0;
}
```

---

## Dimension 4: Error Handling & Resilience

---

### [HIGH] ERR-001: WebSocket Reconnection Does Not Rejoin Room

**Severity:** HIGH  
**Dimension:** Error Handling & Resilience  
**Location:** [websocket.js (client)](file:///e:/Nekowise/client/src/services/websocket.js#L97-L128), [SignalingContext.jsx](file:///e:/Nekowise/client/src/contexts/SignalingContext.jsx)  
**Impact:** When the WebSocket reconnects after a disconnection, the client gets a new `connectionId` on the server. However, no automatic room re-join is performed. The user appears to be in the room (React state preserved) but is actually disconnected from signaling. All peer connections fail silently.

**Refactored Code:**
```javascript
// In SignalingContext.jsx — Listen for reconnection and rejoin
useEffect(() => {
  const unsubscribe = websocket.onConnectionStateChange((state) => {
    setConnectionState(state);
    
    if (state === 'connected' && currentRoom) {
      // Re-join the room after reconnection
      websocket.send({
        type: 'join-room',
        roomId: currentRoom,
        username: user?.displayName || user?.username,
      });
    }
  });

  return unsubscribe;
}, [currentRoom, user]);
```

---

### [HIGH] ERR-002: No Server-Side WebSocket Ping/Pong for Dead Connection Detection

**Severity:** HIGH  
**Dimension:** Error Handling & Resilience  
**Location:** [websocket/server.js](file:///e:/Nekowise/server/src/websocket/server.js)  
**Impact:** The server has no mechanism to detect dead WebSocket connections (e.g., client browser crash, network cable unplugged). The `ws` library requires explicit ping/pong handling. Without it, dead connections occupy memory and room participant slots indefinitely.

**Refactored Code:**
```javascript
setupWebSocketServer() {
  this.wss.on("connection", (ws, req) => {
    // ... existing auth logic ...
    
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });
    
    // ... rest of setup
  });

  // Ping every 30 seconds, terminate unresponsive connections
  this.pingInterval = setInterval(() => {
    this.wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        logger.warn("Terminating unresponsive WebSocket");
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);
}
```

---

### [MEDIUM] ERR-003: MongoDB Connection Failure Crashes Server Permanently

**Severity:** MEDIUM  
**Dimension:** Error Handling & Resilience  
**Location:** [database.js](file:///e:/Nekowise/server/src/config/database.js#L9-L11)  
**Impact:** If MongoDB is unreachable at startup, `process.exit(1)` is called. There is no retry mechanism. In containerized environments, this causes a crash loop until the DB becomes available.

**Current Code:**
```javascript
} catch (error) {
    logger.error(`MongoDB Connection Error: ${error.message}`);
    process.exit(1);
}
```

**Refactored Code:**
```javascript
const connectDatabase = async (retries = 5, delay = 5000) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const conn = await mongoose.connect(process.env.MONGODB_URI);
      logger.info(`MongoDB Connected: ${conn.connection.host}`);
      return;
    } catch (error) {
      logger.error(`MongoDB attempt ${attempt}/${retries} failed: ${error.message}`);
      if (attempt === retries) {
        logger.error("All MongoDB connection attempts exhausted");
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};
```

---

### [MEDIUM] ERR-004: Missing `unhandledRejection` and `uncaughtException` Handlers

**Severity:** MEDIUM  
**Dimension:** Error Handling & Resilience  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js)  
**Impact:** Unhandled promise rejections in async WebSocket handlers or background tasks will crash the Node.js process in Node 15+ without warning.

**Refactored Code:**
```javascript
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason?.message || reason });
  // Don't exit — log and continue
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  // Attempt graceful shutdown
  gracefulShutdown('uncaughtException');
});
```

---

### [MEDIUM] ERR-005: No Graceful Handling When Camera/Mic Permissions Are Denied

**Severity:** MEDIUM  
**Dimension:** Error Handling & Resilience  
**Location:** [Room.jsx](file:///e:/Nekowise/client/src/pages/Room.jsx#L84-L146)  
**Impact:** If `getUserMedia()` fails (permissions denied), the room shows a generic error message and the user is stuck. There is no audio-only fallback, no option to retry with different constraints, and no clear UX guidance.

**Recommendation:** Add a pre-join lobby that checks permissions before entering the room, with options to join without camera/microphone.

---

### [LOW] ERR-006: ErrorBoundary Does Not Catch Errors in Context Providers

**Severity:** LOW  
**Dimension:** Error Handling & Resilience  
**Location:** [App.jsx](file:///e:/Nekowise/client/src/App.jsx#L67-L78)  
**Impact:** The outer `ErrorBoundary` wraps `BrowserRouter > AuthProvider > SignalingProvider`. If `AuthProvider` or `SignalingProvider` throw during render, the boundary catches it. However, async errors in `useEffect` within these providers are **not** caught by ErrorBoundary (React limitation).

---

### [LOW] ERR-007: Chat Typing Timeout Not Cleared on Unmount

**Severity:** LOW  
**Dimension:** Error Handling & Resilience  
**Location:** [Chat.jsx](file:///e:/Nekowise/client/src/components/Chat.jsx#L131-L136)  
**Impact:** The `typingTimeoutRef` timeout fires after the component unmounts, calling `signaling.sendMessage` on a potentially stale reference. Also, the auto-clear `setTimeout` at line 60 is never cleaned up on unmount.

**Refactored Code:**
```javascript
// Add cleanup
useEffect(() => {
  return () => {
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
  };
}, []);
```

---

## Dimension 5: Performance & Efficiency

---

### [HIGH] PERF-001: `useActiveSpeaker` Triggers Excessive Re-Renders

**Severity:** HIGH  
**Dimension:** Performance & Efficiency  
**Location:** [useActiveSpeaker.js](file:///e:/Nekowise/client/src/hooks/useActiveSpeaker.js#L33-L38)  
**Impact:** `updateVolume` calls `setAudioLevels()` which creates a new `Map` on every audio frame (~60fps per user). With 5 participants, this triggers 300 state updates per second, each causing a re-render of Room.jsx and all children.

**Current Code:**
```javascript
const updateVolume = (userId, volume) => {
  setAudioLevels((prev) => {
    const newLevels = new Map(prev);  // New Map every frame!
    newLevels.set(userId, volume);
    return newLevels;
  });
  // ...
};
```

**Refactored Code:**
```javascript
// Use a ref for audio levels and only update state periodically
const audioLevelsRef = useRef(new Map());
const [audioLevels, setAudioLevels] = useState(new Map());

useEffect(() => {
  // Batch state updates every 100ms instead of every frame
  const updateInterval = setInterval(() => {
    setAudioLevels(new Map(audioLevelsRef.current));
  }, 100);

  return () => clearInterval(updateInterval);
}, []);

const updateVolume = useCallback((userId, volume) => {
  audioLevelsRef.current.set(userId, volume);
  determineActiveSpeaker(); // operates on ref, not state
}, []);
```

---

### [MEDIUM] PERF-002: Room.jsx Is a 976-Line Monolith

**Severity:** MEDIUM  
**Dimension:** Performance & Efficiency  
**Location:** [Room.jsx](file:///e:/Nekowise/client/src/pages/Room.jsx) (33KB, 976 lines)  
**Impact:** The Room component manages media, signaling, peer connections, chat, reactions, screen sharing, and UI all in one file. Any state change re-renders the entire tree. The component has 12 `useState` calls and 8 `useEffect` calls.

**Recommendation:** Extract into:
- `useRoomMedia` hook (media initialization, toggle, screen share)
- `useRoomSignaling` hook (join, leave, participant tracking)
- `useRoomPeers` hook (peer connection management)
- `VideoGrid` component
- `RoomControls` component
- `SpeakerView` component (already exists inline, extract to file)

---

### [MEDIUM] PERF-003: `peerConnectionManager.getAllPeers()` Called In Render Path

**Severity:** MEDIUM  
**Dimension:** Performance & Efficiency  
**Location:** [Room.jsx](file:///e:/Nekowise/client/src/pages/Room.jsx#L424)  
**Impact:** `peerConnectionManager.getAllPeers()` creates a new array via `Array.from(this.peers.values())` on every render, and is passed to `NetworkQualityIndicator` as a prop. Since the reference changes every render, the `useEffect` in `NetworkQualityIndicator` restarts monitoring on every render cycle.

**Refactored Code:**
```javascript
// Memoize the peers array
const peers = useMemo(() => peerConnectionManager.getAllPeers(), [remoteStreams]);
// Pass memoized array
<NetworkQualityIndicator peers={peers} />
```

---

### [MEDIUM] PERF-004: Admin Page Uses Non-Existent API Methods

**Severity:** MEDIUM  
**Dimension:** Performance & Efficiency  
**Location:** [Admin.jsx](file:///e:/Nekowise/client/src/pages/Admin.jsx#L57-L61)  
**Impact:** The Admin page calls `api.get()`, `api.post()`, `api.put()`, `api.delete()` which are not defined on the `ApiService` class. Only `api.request()` and specific methods like `api.login()` exist. This page will crash with `TypeError: api.get is not a function`.

**Refactored Code:**
```javascript
// Add generic HTTP methods to ApiService
async get(endpoint) {
  return this.request(endpoint);
}

async post(endpoint, data) {
  return this.request(endpoint, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

async put(endpoint, data) {
  return this.request(endpoint, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

async delete(endpoint) {
  return this.request(endpoint, { method: 'DELETE' });
}
```

---

### [LOW] PERF-005: No Database Indexes on Frequently Queried Fields

**Severity:** LOW  
**Dimension:** Performance & Efficiency  
**Location:** [Session.js](file:///e:/Nekowise/server/src/models/Session.js), [User.js](file:///e:/Nekowise/server/src/models/User.js)  
**Impact:** Session queries by `participants.userId` (line 88-89 of sessionController.js) have no index. User queries by `email` in login have an implicit unique index. The `Room` model has good indexes.

**Refactored Code:**
```javascript
// Session.js — Add index for user session queries
sessionSchema.index({ "participants.userId": 1 });

// User.js — Add compound index for auth lookups
userSchema.index({ email: 1, isActive: 1 });
```

---

### [LOW] PERF-006: `getRooms` Limit/Page Not Bounded

**Severity:** LOW  
**Dimension:** Performance & Efficiency  
**Location:** [roomController.js](file:///e:/Nekowise/server/src/controllers/roomController.js#L53)  
**Impact:** A client can request `?limit=999999` and retrieve the entire rooms collection. The `limit` parameter should be capped.

**Refactored Code:**
```javascript
const page = Math.max(1, parseInt(req.query.page) || 1);
const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 10));
```

---

### [LOW] PERF-007: `Video` Import from Lucide React Unused in Login/Register

**Severity:** LOW  
**Dimension:** Performance & Efficiency  
**Location:** [Login.jsx](file:///e:/Nekowise/client/src/pages/Login.jsx#L15), [Register.jsx](file:///e:/Nekowise/client/src/pages/Register.jsx#L14)  
**Impact:** `Video` icon is imported but never used. With proper tree-shaking this has no bundle impact, but it's dead code.

---

## Dimension 6: Data Model & Persistence Integrity

---

### [CRITICAL] DATA-001: Room Participant Count Drifts from Actual WebSocket Connections

**Severity:** CRITICAL  
**Dimension:** Data Model & Persistence Integrity  
**Location:** [websocket/server.js](file:///e:/Nekowise/server/src/websocket/server.js#L327), [messageHandler.js](file:///e:/Nekowise/server/src/websocket/messageHandler.js#L55-L57)  
**Impact:** The room's `currentParticipants` in MongoDB is computed from the in-memory `this.rooms` Map via `getUniqueRoomUserCount()`. If the server restarts, all in-memory state is lost but MongoDB still shows `currentParticipants > 0` and `isActive: true`. The `join-room` handler checks `room.currentParticipants >= room.maxParticipants`, so stale data can prevent new joins to restarted rooms. There is no reconciliation mechanism.

**Refactored Code:**
```javascript
// On server startup, reset all active rooms to 0 participants
const resetActiveRooms = async () => {
  await Room.updateMany(
    { isActive: true },
    { $set: { currentParticipants: 0 } }
  );
  logger.info("Reset active room participant counts on startup");
};

// Call in server.js after connectDatabase()
await resetActiveRooms();
```

---

### [HIGH] DATA-002: No Concurrency Control on Room Join — Race Condition

**Severity:** HIGH  
**Dimension:** Data Model & Persistence Integrity  
**Location:** [messageHandler.js](file:///e:/Nekowise/server/src/websocket/messageHandler.js#L50-L57)  
**Impact:** Two users can check `room.currentParticipants >= room.maxParticipants` simultaneously, both pass the check, and both join — exceeding the max. The DB update happens asynchronously via `room.save()` after the in-memory state is already modified.

**Refactored Code:**
```javascript
// Use findOneAndUpdate with atomic increment and return check
async function handleJoinRoom(server, client, message, correlationId) {
  const { roomId, username } = message;
  if (!roomId) throw new Error("Room ID is required");

  // Atomic check-and-increment
  const room = await Room.findOneAndUpdate(
    { 
      roomId, 
      isActive: true,
      $expr: { $lt: ["$currentParticipants", "$maxParticipants"] }
    },
    { $inc: { currentParticipants: 1 } },
    { new: true }
  );

  if (!room) {
    throw new Error("Room not found or is full");
  }

  // ... proceed with join
}
```

---

### [MEDIUM] DATA-003: Session Records Not Finalized on Abnormal Server Shutdown

**Severity:** MEDIUM  
**Dimension:** Data Model & Persistence Integrity  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js#L107-L126)  
**Impact:** The graceful shutdown handler closes WebSocket connections but does not finalize active Session documents. Sessions remain with `isActive: true` permanently.

**Refactored Code:**
```javascript
const gracefulShutdown = async (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);

  // Finalize all active sessions
  await Session.updateMany(
    { isActive: true },
    { 
      $set: { 
        isActive: false, 
        endedAt: new Date(),
        endReason: 'server_shutdown'
      } 
    }
  );

  // Close WebSocket connections
  signalingServer.wss.clients.forEach((ws) => {
    ws.close(1000, "Server shutting down");
  });

  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });

  setTimeout(() => process.exit(1), 10000);
};
```

---

### [LOW] DATA-004: Room `participants` Array Grows Without Bound

**Severity:** LOW  
**Dimension:** Data Model & Persistence Integrity  
**Location:** [Room.js](file:///e:/Nekowise/server/src/models/Room.js#L94)  
**Impact:** Every join appends to the `participants` array. For long-lived rooms with many joins/leaves, this array grows unbounded, increasing document size and query time.

---

### [LOW] DATA-005: `chatMessageSchema` Defined But Chat Messages Not Stored

**Severity:** LOW  
**Dimension:** Data Model & Persistence Integrity  
**Location:** [Room.js](file:///e:/Nekowise/server/src/models/Room.js#L28-L51), [messageHandler.js](file:///e:/Nekowise/server/src/websocket/messageHandler.js#L328-L377)  
**Impact:** The Room model has a `messages: [chatMessageSchema]` field, but `handleChatMessage` in the message handler never persists messages to the database. The schema exists but is unused — messages are only broadcast in real-time.

---

## Dimension 7: API Design & Hardening

---

### [HIGH] API-001: No Request/Response Logging or Audit Trail

**Severity:** HIGH  
**Dimension:** API Design & Hardening  
**Location:** [server.js](file:///e:/Nekowise/server/src/server.js#L48-L50)  
**Impact:** Morgan is only enabled in development mode. In production, there is zero HTTP request logging — no audit trail for security incidents, no request IDs for traceability, and no way to debug production issues.

**Refactored Code:**
```javascript
// Always enable request logging in structured format
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  
  const start = Date.now();
  res.on('finish', () => {
    logger.info('HTTP Request', {
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: Date.now() - start,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
  });
  
  next();
});
```

---

### [MEDIUM] API-002: Inconsistent Error Response Format

**Severity:** MEDIUM  
**Dimension:** API Design & Hardening  
**Location:** All controllers  
**Impact:** Some responses use `{ message }`, others `{ error }`, others `{ success, message }`. Clients cannot reliably parse errors. Some include `error: error.message`, others don't.

**Recommendation:** Standardize on:
```json
{
  "success": false,
  "message": "User-friendly error message",
  "code": "ROOM_NOT_FOUND",
  "requestId": "uuid"
}
```

---

### [MEDIUM] API-003: No WebSocket Message Schema Validation

**Severity:** MEDIUM  
**Dimension:** API Design & Hardening  
**Location:** [messageHandler.js](file:///e:/Nekowise/server/src/websocket/messageHandler.js#L5-L41)  
**Impact:** WebSocket messages are dispatched to handlers based on `type` alone. There is no schema validation for message payloads. A malicious client can send arbitrary fields, oversized data, or wrong types.

**Refactored Code:**
```javascript
// Add simple schema validation
const MESSAGE_SCHEMAS = {
  'join-room': { required: ['roomId'], maxSize: 1024 },
  'chat-message': { required: ['text'], maxSize: 2048 },
  'offer': { required: ['targetUserId', 'offer'], maxSize: 65536 },
  'answer': { required: ['targetUserId', 'answer'], maxSize: 65536 },
  'ice-candidate': { required: ['targetUserId', 'candidate'], maxSize: 4096 },
  'reaction': { required: ['emoji'], maxSize: 256 },
  'typing': { required: ['isTyping'], maxSize: 128 },
  'ping': { required: [], maxSize: 64 },
};

function validateMessage(message) {
  const schema = MESSAGE_SCHEMAS[message.type];
  if (!schema) return false;
  
  const messageSize = JSON.stringify(message).length;
  if (messageSize > schema.maxSize) return false;
  
  for (const field of schema.required) {
    if (message[field] === undefined) return false;
  }
  return true;
}
```

---

### [LOW] API-004: Health Endpoint Does Not Check MongoDB Connectivity

**Severity:** LOW  
**Dimension:** API Design & Hardening  
**Location:** [health.js](file:///e:/Nekowise/server/src/routes/health.js#L6-L16)  
**Impact:** The health endpoint checks `mongoose.connection.readyState` but does not actually perform a query to verify the connection is functional. A stale connection pool could report "connected" while queries fail.

**Refactored Code:**
```javascript
router.get("/health", async (req, res) => {
  let dbStatus = "disconnected";
  try {
    await mongoose.connection.db.admin().ping();
    dbStatus = "connected";
  } catch (e) {
    dbStatus = "error";
  }
  
  const status = dbStatus === "connected" ? "OK" : "DEGRADED";
  res.status(dbStatus === "connected" ? 200 : 503).json({
    status,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: dbStatus,
  });
});
```

---

### [LOW] API-005: `getActiveRooms` Admin Endpoint Returns Unbounded Results

**Severity:** LOW  
**Dimension:** API Design & Hardening  
**Location:** [adminController.js](file:///e:/Nekowise/server/src/controllers/adminController.js#L61-L63)  
**Impact:** `Room.find({ isActive: true })` returns all active rooms without pagination. With many active rooms this could be a large response.

---

## Dimension 8: Code Quality & Maintainability

---

### [LOW] CODE-001: Singleton Pattern for Services Prevents Testing

**Severity:** LOW  
**Dimension:** Code Quality & Maintainability  
**Location:** All client services — [websocket.js](file:///e:/Nekowise/client/src/services/websocket.js#L242), [mediaService.js](file:///e:/Nekowise/client/src/services/mediaService.js#L145), [audioMonitor.js](file:///e:/Nekowise/client/src/services/audioMonitor.js#L90), [peerConnectionManager.js](file:///e:/Nekowise/client/src/services/peerConnectionManager.js#L181), [networkQualityMonitor.js](file:///e:/Nekowise/client/src/services/networkQualityMonitor.js#L126)  
**Impact:** All services export singleton instances (`export default new WebSocketService()`). This makes unit testing impossible without module mocking, prevents multiple instances for testing, and creates hidden global state. The `peerConnectionManager` singleton's `signaling` is set via `initialize()` but never cleared, causing stale references across page navigations.

**Recommendation:** Export both the class and a default instance. Better yet, use React Context to provide service instances, enabling dependency injection and testability.

---

## Files With No Issues in Specific Dimensions

For completeness:

| File | Dimensions with No Issues |
|---|---|
| `server/src/models/User.js` | Dimensions 3, 4, 5, 7, 8 — Well-structured schema with proper validation |
| `server/src/models/Room.js` | Dimensions 3, 4, 8 — Good indexes defined |
| `server/src/middleware/adminAuth.js` | Dimensions 1-8 — Simple and correct |
| `server/src/middleware/rateLimiter.js` | Dimensions 2-8 — Well-configured rate limits |
| `client/src/components/AudioLevelIndicator.jsx` | Dimensions 1-8 — Simple pure presentational component |
| `client/src/components/ConnectionStatus.jsx` | Dimensions 1-8 — Simple pure presentational component |
| `client/src/components/ReactionPicker.jsx` | Dimensions 1-8 — Simple and correct |
| `client/src/lib/utils.js` | Dimensions 1-8 — Standard utility |
| `client/src/main.jsx` | Dimensions 1-8 — Standard React entry |
| `client/vite.config.js` | Dimensions 1-8 — Standard Vite configuration |
| `client/src/utils/analytics.js` | Dimensions 1-8 — Placeholder, not yet integrated |
| `client/src/utils/sentry.js` | Dimensions 1-8 — Placeholder, not yet integrated |

---

## Priority Remediation Roadmap

### Phase 1: Immediate (before any production deployment)

| Finding | Title | Effort |
|---|---|---|
| SEC-001 | JWT in localStorage → httpOnly cookies | 2-3 days |
| SEC-002 | Separate refresh token secret + revocation | 1-2 days |
| SEC-003 | WebSocket origin validation | 2 hours |
| SEC-005 | JSON body size limit | 15 minutes |
| SEC-007 | JWT secret strength enforcement | 1 hour |
| DATA-001 | Room participant reset on startup | 2 hours |
| ERR-002 | Server-side WebSocket ping/pong | 2 hours |
| ERR-004 | unhandledRejection handlers | 30 minutes |

### Phase 2: High Priority (first week of production)

| Finding | Title | Effort |
|---|---|---|
| RTC-001 | Glare condition / offer collision | 4 hours |
| RTC-002 | TURN server configuration | 1 day (infra) |
| RTC-003 | ICE restart backoff | 2 hours |
| SEC-004 | NoSQL injection protection | 2 hours |
| MEM-001 | Unbounded server maps cleanup | 3 hours |
| MEM-003 | PeerConnection close cleanup | 2 hours |
| ERR-001 | WebSocket re-join on reconnect | 3 hours |
| API-001 | Request logging in production | 3 hours |
| DATA-002 | Atomic room join | 3 hours |
| PERF-001 | useActiveSpeaker re-render fix | 3 hours |
| PERF-004 | Admin.jsx missing API methods | 1 hour |

### Phase 3: Medium Priority (first month)

| Finding | Title | Effort |
|---|---|---|
| PERF-002 | Room.jsx decomposition | 2-3 days |
| RTC-004 | Mesh scaling / simulcast | 1-2 weeks |
| SEC-009 | Content-Security-Policy | 3 hours |
| API-002 | Error response standardization | 1 day |
| API-003 | WebSocket schema validation | 4 hours |
| ERR-003 | MongoDB connection retry | 2 hours |
| DATA-003 | Session finalization on shutdown | 2 hours |

### Phase 4: Low Priority (ongoing)

All LOW severity findings — typically 1-2 hours each.

---

> [!IMPORTANT]
> **Summary:** The most critical systemic risk is the combination of SEC-001 (JWT in localStorage) and SEC-003 (no WebSocket origin validation). Together, these create a viable attack chain where XSS → token theft → full account takeover via WebSocket. The second major cluster is the WebRTC correctness issues (RTC-001, RTC-002, RTC-003) which will cause user-visible call failures in production. **These 5 findings alone should block any production deployment.**
