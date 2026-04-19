import logger from "./logger.js";

// SEC-007: Require JWT_REFRESH_SECRET alongside JWT_SECRET
const requiredEnvVars = [
  "MONGODB_URI",
  "JWT_SECRET",
  "JWT_REFRESH_SECRET", // SEC-002: separate refresh secret
  "CLIENT_URL",
  "JWT_EXPIRE",
  "JWT_REFRESH_EXPIRE",
];

const validateEnv = () => {
  const missing = requiredEnvVars.filter((varName) => !process.env[varName]);
  if (missing.length > 0) {
    logger.error(
      `Missing required environment variables: ${missing.join(", ")}`
    );
    process.exit(1);
  }

  // SEC-007: Enforce minimum JWT secret strength
  if (process.env.JWT_SECRET.length < 32) {
    logger.error(
      "JWT_SECRET must be at least 32 characters for production security"
    );
    process.exit(1);
  }

  if (
    process.env.JWT_SECRET.includes("change_in_production") ||
    process.env.JWT_SECRET ===
      "your_super_secret_jwt_key_change_in_production"
  ) {
    logger.error(
      "JWT_SECRET contains default value — must be changed for production"
    );
    process.exit(1);
  }

  // SEC-007: Enforce minimum refresh secret strength
  if (process.env.JWT_REFRESH_SECRET.length < 32) {
    logger.error(
      "JWT_REFRESH_SECRET must be at least 32 characters for production security"
    );
    process.exit(1);
  }

  // SEC-008: Enforce HTTPS in production
  if (
    process.env.NODE_ENV === "production" &&
    !process.env.CLIENT_URL?.startsWith("https://")
  ) {
    logger.error("CLIENT_URL must use HTTPS in production");
    process.exit(1);
  }

  logger.info("Environment variables validated successfully");
};

export default validateEnv;
