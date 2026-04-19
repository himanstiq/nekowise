export const STUN_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun2.l.google.com:19302" },
  { urls: "stun:stun3.l.google.com:19302" },
  { urls: "stun:stun4.l.google.com:19302" },
];

// RTC-002: Build ICE server list with TURN support for production
// Without TURN, ~10-15% of users behind symmetric NATs cannot connect
const buildIceServers = () => {
  const servers = [...STUN_SERVERS];

  if (import.meta.env.VITE_TURN_URL) {
    servers.push({
      urls: import.meta.env.VITE_TURN_URL,
      username: import.meta.env.VITE_TURN_USERNAME || "",
      credential: import.meta.env.VITE_TURN_CREDENTIAL || "",
    });
  }

  return servers;
};

export const RTC_CONFIG = {
  iceServers: buildIceServers(), // RTC-002: Includes TURN when configured
  iceCandidatePoolSize: 10,
  bundlePolicy: "max-bundle",
  rtcpMuxPolicy: "require",
  iceTransportPolicy: "all",
};

// Google Meet level audio constraints
const AUDIO_CONSTRAINTS = {
  echoCancellation: true,
  noiseSuppression: true,
  autoGainControl: true,
  sampleRate: 48000,
  channelCount: 1,
  latency: 0,
};

// Video quality profiles (similar to Google Meet)
export const VIDEO_QUALITY_PROFILES = {
  "360p": {
    width: { ideal: 640, max: 640 },
    height: { ideal: 360, max: 360 },
    frameRate: { ideal: 24, max: 24 },
    maxBitrate: 500000, // 500 kbps
  },
  "480p": {
    width: { ideal: 854, max: 854 },
    height: { ideal: 480, max: 480 },
    frameRate: { ideal: 24, max: 30 },
    maxBitrate: 1000000, // 1 Mbps
  },
  "720p": {
    width: { ideal: 1280, max: 1280 },
    height: { ideal: 720, max: 720 },
    frameRate: { ideal: 30, max: 30 },
    maxBitrate: 2500000, // 2.5 Mbps
  },
  "1080p": {
    width: { ideal: 1920, max: 1920 },
    height: { ideal: 1080, max: 1080 },
    frameRate: { ideal: 30, max: 30 },
    maxBitrate: 4000000, // 4 Mbps
  },
};

// Default to 720p for optimal quality/bandwidth balance
export const MEDIA_CONSTRAINTS = {
  audio: AUDIO_CONSTRAINTS,
  video: {
    ...VIDEO_QUALITY_PROFILES["720p"],
    facingMode: "user",
    aspectRatio: 16 / 9,
  },
};

// Function to get constraints for specific quality
export function getMediaConstraints(quality = "720p") {
  const profile =
    VIDEO_QUALITY_PROFILES[quality] || VIDEO_QUALITY_PROFILES["720p"];
  return {
    audio: AUDIO_CONSTRAINTS,
    video: {
      ...profile,
      facingMode: "user",
      aspectRatio: 16 / 9,
    },
  };
}

// For lower bandwidth (adaptive quality)
export const MEDIA_CONSTRAINTS_LOW = {
  audio: AUDIO_CONSTRAINTS,
  video: {
    ...VIDEO_QUALITY_PROFILES["360p"],
    facingMode: "user",
    aspectRatio: 16 / 9,
  },
};
