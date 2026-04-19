import { verifyToken } from "../utils/jwt.js";
import User from "../models/User.js";
import logger from "../utils/logger.js";

export const protect = async (req, res, next) => {
  try {
    let token;

    // SEC-001: Read token from httpOnly cookie first, fall back to Authorization header
    if (req.cookies?.token) {
      token = req.cookies.token;
    } else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return res.status(401).json({ message: "Not authorized, no token" });
    }

    const decoded = verifyToken(token);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (!user.isActive) {
      return res.status(401).json({ message: "User account is inactive" });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error("Auth middleware error", { error: error.message });
    return res.status(401).json({ message: "Not authorized, token failed" });
  }
};
