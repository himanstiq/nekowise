import jwt from "jsonwebtoken";
import logger from "./logger.js";

// SEC-002: Include token type in payload to distinguish access from refresh tokens
export const generateToken = (userId, expiresIn = process.env.JWT_EXPIRE) => {
  try {
    return jwt.sign({ id: userId, type: "access" }, process.env.JWT_SECRET, {
      expiresIn,
    });
  } catch (error) {
    logger.error("Error generating token", { error: error.message });
    throw error;
  }
};

export const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    logger.error("Error verifying token", { error: error.message });
    throw error;
  }
};

// SEC-002: Use a separate secret for refresh tokens to prevent token-type confusion
export const generateRefreshToken = (userId) => {
  try {
    return jwt.sign(
      { id: userId, type: "refresh" },
      process.env.JWT_REFRESH_SECRET, // SEC-002: separate secret
      { expiresIn: process.env.JWT_REFRESH_EXPIRE }
    );
  } catch (error) {
    logger.error("Error generating refresh token", { error: error.message });
    throw error;
  }
};

// SEC-002: Dedicated refresh token verification with type checking
export const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    if (decoded.type !== "refresh") {
      throw new Error("Invalid token type");
    }
    return decoded;
  } catch (error) {
    logger.error("Error verifying refresh token", { error: error.message });
    throw error;
  }
};
