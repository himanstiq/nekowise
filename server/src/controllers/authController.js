import User from "../models/User.js";
import {
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import logger from "../utils/logger.js";

// SEC-001: Helper to set httpOnly auth cookies — tokens never exposed to JS
const setAuthCookies = (res, token, refreshTokenValue) => {
  const isProduction = process.env.NODE_ENV === "production";

  res.cookie("token", token, {
    httpOnly: true, // SEC-001: Not accessible via document.cookie
    secure: isProduction, // SEC-001: Require HTTPS in production
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.cookie("refreshToken", refreshTokenValue, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: "/api/auth/refresh", // SEC-001: Only sent to the refresh endpoint
  });
};

export const register = async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    // SEC-004: Validate input types to prevent NoSQL injection
    if (
      !username ||
      typeof username !== "string" ||
      !email ||
      typeof email !== "string" ||
      !password ||
      typeof password !== "string"
    ) {
      return res
        .status(400)
        .json({ message: "Please provide all required fields" });
    }

    // SEC-004: Coerce to string before querying
    const existingUser = await User.findOne({
      $or: [{ email: String(email) }, { username: String(username) }],
    });

    if (existingUser) {
      return res.status(400).json({
        message:
          existingUser.email === email
            ? "Email already registered"
            : "Username already taken",
      });
    }

    const user = await User.create({
      username: String(username),
      email: String(email),
      password: String(password),
      displayName: displayName ? String(displayName) : username,
    });

    const token = generateToken(user._id);
    const refreshTokenValue = generateRefreshToken(user._id);

    // SEC-001: Set tokens as httpOnly cookies instead of response body
    setAuthCookies(res, token, refreshTokenValue);

    logger.info("User registered successfully", {
      userId: user._id,
      username,
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    logger.error("Registration error", { error: error.message });
    res.status(500).json({ message: "Error registering user" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // SEC-004: Validate input types to prevent NoSQL injection
    if (
      !email ||
      typeof email !== "string" ||
      !password ||
      typeof password !== "string"
    ) {
      return res
        .status(400)
        .json({ message: "Please provide email and password" });
    }

    // SEC-004: Coerce to string before querying
    const user = await User.findOne({ email: String(email) }).select(
      "+password"
    );

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.isActive) {
      return res.status(401).json({ message: "Account is inactive" });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    user.lastLogin = Date.now();
    await user.save();

    const token = generateToken(user._id);
    const refreshTokenValue = generateRefreshToken(user._id);

    // SEC-001: Set tokens as httpOnly cookies instead of response body
    setAuthCookies(res, token, refreshTokenValue);

    logger.info("User logged in successfully", {
      userId: user._id,
      username: user.username,
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    logger.error("Login error", { error: error.message });
    res.status(500).json({ message: "Error logging in" });
  }
};

export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    // AUDIT: Guard against user deleted between auth middleware and this query
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatar: user.avatar,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    logger.error("Get me error", { error: error.message });
    res.status(500).json({ message: "Error fetching user" });
  }
};

// SEC-002: Use dedicated verifyRefreshToken with separate secret and type check
export const refreshToken = async (req, res) => {
  try {
    // SEC-001: Read refresh token from httpOnly cookie
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(400).json({ message: "Refresh token required" });
    }

    // SEC-002: Verify with separate secret; rejects access tokens used as refresh
    const decoded = verifyRefreshToken(token);
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const newToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // SEC-001: Rotate cookies
    setAuthCookies(res, newToken, newRefreshToken);

    res.status(200).json({
      success: true,
    });
  } catch (error) {
    logger.error("Refresh token error", { error: error.message });
    res.status(401).json({ message: "Invalid refresh token" });
  }
};

// SEC-001: Generate short-lived ticket for WebSocket authentication
export const generateWsTicket = async (req, res) => {
  try {
    // Issue a 30-second ticket so the real token never appears in a URL
    const ticket = generateToken(req.user.id, "30s");
    res.status(200).json({ success: true, ticket });
  } catch (error) {
    logger.error("WS ticket generation error", { error: error.message });
    res.status(500).json({ message: "Error generating WebSocket ticket" });
  }
};

// SEC-001: Server-side logout clears httpOnly cookies
export const logout = async (req, res) => {
  res.clearCookie("token");
  res.clearCookie("refreshToken", { path: "/api/auth/refresh" });
  res.status(200).json({ success: true, message: "Logged out successfully" });
};
