import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import PropTypes from "prop-types";
import { useAuth } from "../contexts/AuthContext";
import { useSignaling } from "../contexts/SignalingContext";
import { useActiveSpeaker } from "../hooks/useActiveSpeaker";
import Container from "../components/Layout/Container";
import AudioLevelIndicator from "../components/AudioLevelIndicator";
import NetworkQualityIndicator from "../components/NetworkQualityIndicator";
import Chat from "../components/Chat";
import QualitySelector from "../components/QualitySelector";
import ReactionPicker from "../components/ReactionPicker";
import ReactionOverlay from "../components/ReactionOverlay";
import mediaService from "../services/mediaService";
import peerConnectionManager from "../services/peerConnectionManager";
import { Logger } from "../utils/logger";
import {
  Mic,
  MicOff,
  Video as VideoIcon,
  VideoOff,
  MonitorUp,
  LayoutGrid as Grid3x3,
  User,
  Users,
  Phone,
} from "lucide-react";

// Create contextual logger for Room component
const logger = new Logger("Room");

// Helper function to calculate grid layout based on participant count (Google Meet style)
function getGridLayout(participantCount) {
  if (participantCount === 1) {
    return "grid-cols-1 max-w-4xl"; // Single participant - large centered
  } else if (participantCount === 2) {
    return "grid-cols-1 md:grid-cols-2 max-w-6xl"; // 2 participants - side by side
  } else if (participantCount <= 4) {
    return "grid-cols-1 md:grid-cols-2 max-w-6xl"; // 3-4 participants - 2x2 grid
  } else if (participantCount <= 6) {
    return "grid-cols-2 md:grid-cols-3 max-w-7xl"; // 5-6 participants - 2x3 grid
  } else if (participantCount <= 9) {
    return "grid-cols-2 md:grid-cols-3 lg:grid-cols-3 max-w-7xl"; // 7-9 participants - 3x3 grid
  } else {
    return "grid-cols-2 md:grid-cols-3 lg:grid-cols-4 max-w-7xl"; // 10+ participants - 4 columns
  }
}

export default function Room() {
  const { roomId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const signaling = useSignaling();
  const { joinRoom, leaveRoom, isConnected } = signaling;

  const [localStream, setLocalStream] = useState(null);
  const [remoteStreams, setRemoteStreams] = useState(new Map());
  const [isAudioEnabled, setIsAudioEnabled] = useState(true);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [screenStream, setScreenStream] = useState(null);
  const [error, setError] = useState(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [hasJoinedRoom, setHasJoinedRoom] = useState(false);
  const [viewMode, setViewMode] = useState("grid");
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatHistory, setChatHistory] = useState([]);
  const [reactions, setReactions] = useState(new Map()); // Map of userId -> { emoji, timestamp }

  const localVideoRef = useRef(null);
  const processedParticipants = useRef(new Set());

  // Calculate total participant count (local + remote)
  const totalParticipants = remoteStreams.size + 1;

  // Active speaker detection
  const { activeSpeakerId, audioLevels } = useActiveSpeaker(
    Array.from(remoteStreams.values()),
    localStream,
    remoteStreams
  );

  // Initialize room
  useEffect(() => {
    let mounted = true;

    const initialize = async () => {
      if (!isConnected || isInitialized) return;

      try {
        setError(null);
        logger.info("Initializing room...");

        const stream = await mediaService.getUserMedia();

        if (!mounted) {
          mediaService.stopLocalStream();
          return;
        }

        setLocalStream(stream);

        if (localVideoRef.current) {
          localVideoRef.current.srcObject = stream;
        }

        peerConnectionManager.initialize(
          signaling,
          user.id, // RTC-001: Pass local user ID for glare condition handling
          (userId, username, stream) => {
            logger.debug("Received remote stream from", userId, username);
            setRemoteStreams((prev) => {
              const newMap = new Map(prev);
              newMap.set(userId, { userId, username, stream });
              return newMap;
            });
          },
          (userId, state) => {
            logger.debug("Peer connection state:", userId, state);
            if (
              state === "failed" ||
              state === "closed" ||
              state === "disconnected"
            ) {
              setRemoteStreams((prev) => {
                const newMap = new Map(prev);
                newMap.delete(userId);
                return newMap;
              });
            }
          }
        );

        setIsInitialized(true);
      } catch (err) {
        logger.error("Error initializing room", err);
        setError(err.message);
      }
    };

    initialize();

    return () => {
      mounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isConnected, isInitialized]); // Removed 'signaling' to prevent re-initialization

  // Join room
  useEffect(() => {
    if (isInitialized && !hasJoinedRoom) {
      logger.info("Joining room:", roomId);
      joinRoom(roomId, user?.displayName || user?.username);
      setHasJoinedRoom(true);
    }
  }, [isInitialized, hasJoinedRoom, roomId, user, joinRoom]);

  // Handle room-joined message
  useEffect(() => {
    if (!isInitialized) return;

    const unsubscribe = signaling.onMessage("room-joined", (message) => {
      logger.info(
        "Room joined successfully. Existing participants:",
        message.participants?.length || 0
      );

      // Load chat history if provided
      if (message.chatHistory && message.chatHistory.length > 0) {
        logger.debug(
          "Loading chat history:",
          message.chatHistory.length,
          "messages"
        );
        setChatHistory(message.chatHistory);
      }

      if (message.participants && message.participants.length > 0) {
        message.participants.forEach((participant) => {
          if (!processedParticipants.current.has(participant.userId)) {
            logger.debug(
              "Creating offer for existing participant:",
              participant.userId,
              participant.username
            );
            processedParticipants.current.add(participant.userId);
            peerConnectionManager.createOffer(
              participant.userId,
              participant.username
            );
          }
        });
      }
    });

    return unsubscribe;
  }, [isInitialized, signaling]);

  // Handle user-joined message
  useEffect(() => {
    if (!isInitialized) return;

    const unsubscribe = signaling.onMessage("user-joined", (message) => {
      logger.info("New user joined:", message.userId, message.username);

      if (processedParticipants.current.has(message.userId)) {
        logger.debug("Already have connection to", message.userId);
        return;
      }

      logger.debug("Waiting for offer from new user:", message.userId);
      processedParticipants.current.add(message.userId);
    });

    return unsubscribe;
  }, [isInitialized, signaling]);

  // Handle user-left message
  useEffect(() => {
    if (!isInitialized) return;

    const unsubscribe = signaling.onMessage("user-left", (message) => {
      logger.info("User left:", message.userId, message.username);
      processedParticipants.current.delete(message.userId);
    });

    return unsubscribe;
  }, [isInitialized, signaling]);

  // Handle reactions
  useEffect(() => {
    if (!isInitialized) return;

    const unsubscribe = signaling.onMessage("reaction", (message) => {
      logger.debug(
        "Reaction received:",
        message.emoji,
        "from",
        message.username
      );

      setReactions((prev) => {
        const newReactions = new Map(prev);
        newReactions.set(message.userId || message.connectionId, {
          emoji: message.emoji,
          username: message.username,
          timestamp: message.timestamp || Date.now(),
        });
        return newReactions;
      });

      // Auto-remove reaction after 3 seconds
      setTimeout(() => {
        setReactions((prev) => {
          const newReactions = new Map(prev);
          newReactions.delete(message.userId || message.connectionId);
          return newReactions;
        });
      }, 3000);
    });

    return unsubscribe;
  }, [isInitialized, signaling]);

  // Cleanup on unmount
  useEffect(() => {
    const currentProcessedParticipants = processedParticipants.current;

    return () => {
      logger.info("Cleaning up room...");

      // Stop screen share if active
      if (screenStream) {
        screenStream.getTracks().forEach((track) => track.stop());
      }

      leaveRoom();
      peerConnectionManager.closeAllConnections();
      mediaService.stopLocalStream();
      setIsInitialized(false);
      setHasJoinedRoom(false);
      currentProcessedParticipants.clear();
    };
  }, [screenStream, leaveRoom]); // Added dependencies

  const toggleAudio = () => {
    const newState = !isAudioEnabled;
    mediaService.toggleAudio(newState);
    setIsAudioEnabled(newState);
  };

  const toggleVideo = () => {
    const newState = !isVideoEnabled;
    mediaService.toggleVideo(newState);
    setIsVideoEnabled(newState);
  };

  const startScreenShare = async () => {
    try {
      logger.info("Starting screen share...");

      const stream = await mediaService.getDisplayMedia();
      setScreenStream(stream);
      setIsScreenSharing(true);

      // Listen for screen share ending
      const screenTrack = stream.getVideoTracks()[0];
      screenTrack.onended = () => {
        logger.info("Screen share ended by user");
        stopScreenShare();
      };

      // Replace video track in all peer connections
      const peers = peerConnectionManager.getAllPeers();

      for (const peer of peers) {
        const senders = peer.pc.getSenders();
        const videoSender = senders.find((s) => s.track?.kind === "video");

        if (videoSender) {
          await videoSender.replaceTrack(screenTrack);
          logger.debug("Replaced video track with screen for", peer.username);
        }
      }

      // Update local video display
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
        localVideoRef.current.classList.remove("mirror");
      }

      logger.info("Screen sharing started");
    } catch (error) {
      logger.error("Failed to start screen share", error);
      setError(error.message);
      setIsScreenSharing(false);
    }
  };

  const stopScreenShare = async () => {
    try {
      logger.info("Stopping screen share...");

      // Stop screen share tracks
      if (screenStream) {
        screenStream.getTracks().forEach((track) => track.stop());
        setScreenStream(null);
      }

      setIsScreenSharing(false);

      // Replace back to camera track in all peer connections
      const cameraStream = mediaService.getLocalStream();
      if (!cameraStream) {
        logger.warn("No camera stream available");
        return;
      }

      const cameraTrack = cameraStream.getVideoTracks()[0];
      const peers = peerConnectionManager.getAllPeers();

      for (const peer of peers) {
        const senders = peer.pc.getSenders();
        const videoSender = senders.find((s) => s.track?.kind === "video");

        if (videoSender) {
          await videoSender.replaceTrack(cameraTrack);
          logger.debug("Replaced screen with camera track for", peer.username);
        }
      }

      // Update local video display back to camera
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = cameraStream;
        localVideoRef.current.classList.add("mirror");
      }

      logger.info("Screen sharing stopped");
    } catch (error) {
      logger.error("Failed to stop screen share", error);
      setError(error.message);
    }
  };

  const handleLeaveRoom = () => {
    navigate("/dashboard");
  };

  if (error) {
    return (
      <Container>
        <div className="text-center py-16">
          <div className="bg-destructive/10 border border-destructive/30 text-destructive px-4 py-3 rounded-2xl mb-4">
            {error}
          </div>
          <button
            onClick={() => navigate("/dashboard")}
            className="bg-primary text-on-primary px-6 py-2 rounded-2xl hover:bg-primary/90 font-medium"
          >
            Back to Dashboard
          </button>
        </div>
      </Container>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col relative">
      {/* Reaction Overlay */}
      <ReactionOverlay reactions={reactions} />

      {/* Room Info */}
      <div className="bg-surface border-b border-outline px-4 py-2 text-on-surface text-sm flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span>
            Room: {roomId} | Participants: {remoteStreams.size + 1}
          </span>
          {isScreenSharing && (
            <span className="bg-primary px-2 py-1 rounded-full text-xs font-semibold flex items-center gap-1 text-on-primary">
              <MonitorUp className="h-3 w-3" />
              You are presenting
            </span>
          )}
          <NetworkQualityIndicator
            peers={peerConnectionManager.getAllPeers()}
          />
        </div>
        <div className="text-xs text-on-surface-variant">
          {activeSpeakerId &&
            (activeSpeakerId === "local"
              ? "You are speaking"
              : "Someone is speaking")}
        </div>
      </div>

      {/* Video Grid */}
      <div className="flex-1 p-4 overflow-hidden">
        {viewMode === "grid" ? (
          isScreenSharing ||
          Array.from(remoteStreams.values()).some((s) => s.isScreenSharing) ? (
            // Screen Share Layout - Large screen + thumbnails on side
            <div className="flex gap-4 h-full max-w-7xl mx-auto">
              {/* Main screen share area */}
              <div className="flex-1 min-w-0">
                <div className="relative bg-surface-variant rounded-2xl overflow-hidden h-full shadow-md">
                  <video
                    ref={localVideoRef}
                    autoPlay
                    playsInline
                    muted
                    className="w-full h-full object-contain"
                  />

                  {isScreenSharing && (
                    <div className="absolute top-4 left-4 bg-primary text-on-primary px-4 py-2 rounded-2xl text-sm font-bold flex items-center gap-2 shadow-lg">
                      <MonitorUp className="h-5 w-5" />
                      <span>You are presenting</span>
                    </div>
                  )}

                  <div className="absolute bottom-4 left-4 bg-surface/90 backdrop-blur-sm px-4 py-2 rounded-2xl text-on-surface text-sm shadow-md">
                    <div className="flex items-center gap-2">
                      <AudioLevelIndicator
                        level={audioLevels.get("local") || 0}
                        isSpeaking={activeSpeakerId === "local"}
                      />
                      <span className="font-medium">
                        You {isScreenSharing && "(Presenting)"}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Sidebar with participant thumbnails */}
              <div className="w-64 flex flex-col gap-3 overflow-y-auto">
                {/* Local camera thumbnail (if not screen sharing) */}
                {!isScreenSharing && (
                  <div className="relative bg-surface-variant rounded-2xl overflow-hidden aspect-video shrink-0 shadow-sm">
                    <video
                      ref={localVideoRef}
                      autoPlay
                      playsInline
                      muted
                      className="w-full h-full object-cover mirror"
                    />
                    <div className="absolute bottom-2 left-2 bg-surface/90 backdrop-blur-sm px-2 py-1 rounded-full text-on-surface text-xs">
                      You
                    </div>
                    {activeSpeakerId === "local" && (
                      <div className="absolute inset-0 ring-2 ring-primary rounded-2xl"></div>
                    )}
                  </div>
                )}

                {/* Remote participant thumbnails */}
                {Array.from(remoteStreams.values()).map(
                  ({ userId, username, stream }) => (
                    <SidebarThumbnail
                      key={userId}
                      username={username}
                      stream={stream}
                      isActiveSpeaker={activeSpeakerId === userId}
                      audioLevel={audioLevels.get(userId) || 0}
                    />
                  )
                )}
              </div>
            </div>
          ) : (
            // Regular Grid View - No screen sharing - Dynamic sizing based on participant count
            <div
              className={`grid ${getGridLayout(
                totalParticipants
              )} gap-4 mx-auto transition-all duration-300`}
            >
              {/* Local Video */}
              <div
                className={`relative bg-surface-variant rounded-2xl overflow-hidden transition-all shadow-md ${
                  activeSpeakerId === "local"
                    ? "ring-4 ring-primary scale-105"
                    : ""
                } ${totalParticipants <= 2 ? "h-[70vh]" : "aspect-video"}`}
              >
                <video
                  ref={localVideoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover mirror"
                />

                <div className="absolute bottom-2 left-2 bg-surface/90 backdrop-blur-sm px-3 py-1 rounded-full text-on-surface text-sm flex items-center gap-2 shadow-sm">
                  <AudioLevelIndicator
                    level={audioLevels.get("local") || 0}
                    isSpeaking={activeSpeakerId === "local"}
                  />
                  <span>You {!isVideoEnabled && "(Camera Off)"}</span>
                </div>

                {activeSpeakerId === "local" && (
                  <div className="absolute top-2 left-2 bg-primary text-on-primary px-2 py-1 rounded-full text-xs font-bold">
                    SPEAKING
                  </div>
                )}

                {!isVideoEnabled && (
                  <div className="absolute inset-0 flex items-center justify-center bg-surface-variant">
                    <div className="text-on-surface text-6xl font-display">
                      {(user?.displayName ||
                        user?.username)?.[0]?.toUpperCase()}
                    </div>
                  </div>
                )}
              </div>

              {/* Remote Videos */}
              {Array.from(remoteStreams.values()).map(
                ({ userId, username, stream }) => (
                  <RemoteVideo
                    key={userId}
                    username={username}
                    stream={stream}
                    isActiveSpeaker={activeSpeakerId === userId}
                    audioLevel={audioLevels.get(userId) || 0}
                    totalParticipants={totalParticipants}
                  />
                )
              )}

              {/* Waiting for others placeholder */}
              {remoteStreams.size === 0 && (
                <div className="relative bg-surface-variant rounded-2xl overflow-hidden aspect-video flex items-center justify-center h-[70vh] shadow-md">
                  <div className="text-on-surface-variant text-center">
                    <Users className="h-16 w-16 mb-4 mx-auto" />
                    <div>Waiting for others to join...</div>
                  </div>
                </div>
              )}
            </div>
          )
        ) : (
          <SpeakerView
            activeSpeakerId={activeSpeakerId}
            localVideoRef={localVideoRef}
            audioLevels={audioLevels}
            remoteStreams={remoteStreams}
            isScreenSharing={isScreenSharing}
          />
        )}
      </div>

      {/* Controls */}
      <div className="bg-surface border-t border-outline p-4">
        <div className="max-w-7xl mx-auto flex items-center justify-center gap-4">
          <button
            onClick={toggleAudio}
            className={`p-4 rounded-full ${
              isAudioEnabled
                ? "bg-surface-variant hover:bg-primary-container/50"
                : "bg-destructive hover:bg-destructive/90"
            } text-on-surface transition-colors shadow-sm`}
            title={isAudioEnabled ? "Mute" : "Unmute"}
          >
            {isAudioEnabled ? (
              <Mic className="h-6 w-6" />
            ) : (
              <MicOff className="h-6 w-6" />
            )}
          </button>

          <button
            onClick={toggleVideo}
            className={`p-4 rounded-full ${
              isVideoEnabled
                ? "bg-surface-variant hover:bg-primary-container/50"
                : "bg-destructive hover:bg-destructive/90"
            } text-on-surface transition-colors shadow-sm`}
            title={isVideoEnabled ? "Stop Video" : "Start Video"}
          >
            {isVideoEnabled ? (
              <VideoIcon className="h-6 w-6" />
            ) : (
              <VideoOff className="h-6 w-6" />
            )}
          </button>

          <button
            onClick={isScreenSharing ? stopScreenShare : startScreenShare}
            className={`p-4 rounded-full ${
              isScreenSharing
                ? "bg-primary hover:bg-primary/90 ring-2 ring-primary/40 text-on-primary"
                : "bg-surface-variant hover:bg-primary-container/50 text-on-surface"
            } transition-colors shadow-sm`}
            title={isScreenSharing ? "Stop Sharing" : "Share Screen"}
          >
            <MonitorUp className="h-6 w-6" />
          </button>

          <button
            onClick={() =>
              setViewMode(viewMode === "grid" ? "speaker" : "grid")
            }
            className="p-4 rounded-full bg-surface-variant hover:bg-primary-container/50 text-on-surface transition-colors shadow-sm"
            title={
              viewMode === "grid"
                ? "Switch to Speaker View"
                : "Switch to Grid View"
            }
          >
            {viewMode === "grid" ? (
              <User className="h-6 w-6" />
            ) : (
              <Grid3x3 className="h-6 w-6" />
            )}
          </button>

          <ReactionPicker
            onReaction={(emoji) => {
              signaling.sendMessage({
                type: "reaction",
                emoji,
              });
            }}
          />

          <QualitySelector />

          <button
            onClick={handleLeaveRoom}
            className="px-6 py-3 bg-destructive hover:bg-destructive/90 text-destructive-foreground rounded-full transition-colors font-medium flex items-center gap-2 shadow-sm"
          >
            <Phone className="h-5 w-5 rotate-135" />
            Leave Room
          </button>
        </div>
      </div>

      {/* Chat Component */}
      <Chat
        signaling={signaling}
        currentUser={user}
        isOpen={isChatOpen}
        onToggle={() => setIsChatOpen(!isChatOpen)}
        initialMessages={chatHistory}
      />
    </div>
  );
}

function RemoteVideo({
  username,
  stream,
  isActiveSpeaker,
  audioLevel,
  totalParticipants,
}) {
  const videoRef = useRef(null);
  const [playbackError, setPlaybackError] = useState(false);

  useEffect(() => {
    if (videoRef.current && stream) {
      videoRef.current.srcObject = stream;
      videoRef.current.play().catch((error) => {
        logger.warn("Video autoplay failed", {
          username,
          error: error.message,
        });
        setPlaybackError(true);
      });
    }
  }, [stream, username]);

  const handleRetryPlay = () => {
    if (videoRef.current) {
      videoRef.current
        .play()
        .then(() => {
          setPlaybackError(false);
        })
        .catch((error) => {
          logger.error("Retry video play failed", {
            username,
            error: error.message,
          });
        });
    }
  };

  return (
    <div
      className={`relative bg-surface-variant rounded-2xl overflow-hidden transition-all shadow-md ${
        isActiveSpeaker ? "ring-4 ring-primary scale-105" : ""
      } ${totalParticipants <= 2 ? "h-[70vh]" : "aspect-video"}`}
    >
      <video
        ref={videoRef}
        autoPlay
        playsInline
        className="w-full h-full object-cover"
      />

      {playbackError && (
        <div className="absolute inset-0 flex items-center justify-center bg-surface-variant/90 backdrop-blur-sm">
          <button
            onClick={handleRetryPlay}
            className="px-4 py-2 bg-primary hover:bg-primary/90 text-on-primary rounded-2xl shadow-md"
          >
            Click to play video
          </button>
        </div>
      )}

      <div className="absolute bottom-2 left-2 bg-surface/90 backdrop-blur-sm px-3 py-1 rounded-full text-on-surface text-sm flex items-center gap-2 shadow-sm">
        <AudioLevelIndicator
          level={audioLevel || 0}
          isSpeaking={isActiveSpeaker}
        />
        <span>{username}</span>
      </div>
      {isActiveSpeaker && (
        <div className="absolute top-2 left-2 bg-primary text-on-primary px-2 py-1 rounded-full text-xs font-bold">
          SPEAKING
        </div>
      )}
    </div>
  );
}

RemoteVideo.propTypes = {
  username: PropTypes.string.isRequired,
  stream: PropTypes.object.isRequired,
  isActiveSpeaker: PropTypes.bool,
  audioLevel: PropTypes.number,
  totalParticipants: PropTypes.number.isRequired,
};

function SpeakerView({
  activeSpeakerId,
  localVideoRef,
  audioLevels,
  remoteStreams,
  isScreenSharing,
}) {
  const activeSpeakerVideoRef = useRef(null);

  useEffect(() => {
    if (activeSpeakerId && activeSpeakerId !== "local") {
      const activeStream = remoteStreams.get(activeSpeakerId);
      if (activeSpeakerVideoRef.current && activeStream?.stream) {
        activeSpeakerVideoRef.current.srcObject = activeStream.stream;
      }
    }
  }, [activeSpeakerId, remoteStreams]);

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex-1 min-h-0">
        {activeSpeakerId ? (
          activeSpeakerId === "local" ? (
            <div className="relative bg-surface-variant rounded-2xl overflow-hidden h-full ring-4 ring-primary shadow-md">
              <video
                ref={localVideoRef}
                autoPlay
                playsInline
                muted
                className={`w-full h-full object-contain ${
                  !isScreenSharing ? "mirror" : ""
                }`}
              />
              <div className="absolute bottom-4 left-4 bg-surface/90 backdrop-blur-sm px-4 py-2 rounded-2xl text-on-surface shadow-md">
                <div className="flex items-center gap-3">
                  <AudioLevelIndicator
                    level={audioLevels.get("local") || 0}
                    isSpeaking={true}
                  />
                  <span className="text-lg font-semibold">
                    You {isScreenSharing ? "(Sharing)" : "(Speaking)"}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            (() => {
              const activeStream = remoteStreams.get(activeSpeakerId);
              if (!activeStream) return null;
              return (
                <div className="relative bg-surface-variant rounded-2xl overflow-hidden h-full ring-4 ring-primary shadow-md">
                  <video
                    ref={activeSpeakerVideoRef}
                    autoPlay
                    playsInline
                    className="w-full h-full object-contain"
                  />
                  <div className="absolute bottom-4 left-4 bg-surface/90 backdrop-blur-sm px-4 py-2 rounded-2xl text-on-surface shadow-md">
                    <div className="flex items-center gap-3">
                      <AudioLevelIndicator
                        level={audioLevels.get(activeSpeakerId) || 0}
                        isSpeaking={true}
                      />
                      <span className="text-lg font-semibold">
                        {activeStream.username} (Speaking)
                      </span>
                    </div>
                  </div>
                </div>
              );
            })()
          )
        ) : (
          <div className="bg-surface-variant rounded-2xl h-full flex items-center justify-center text-on-surface-variant shadow-md">
            <div className="text-center">
              <Mic className="h-24 w-24 mb-4 mx-auto" />
              <div className="text-xl">Waiting for someone to speak...</div>
            </div>
          </div>
        )}
      </div>

      <div className="flex gap-2 overflow-x-auto pb-2">
        {activeSpeakerId !== "local" && (
          <Thumbnail
            videoRef={localVideoRef}
            username="You"
            isMirrored={true}
          />
        )}

        {Array.from(remoteStreams.values())
          .filter(({ userId }) => userId !== activeSpeakerId)
          .map(({ userId, username, stream }) => (
            <Thumbnail key={userId} username={username} stream={stream} />
          ))}
      </div>
    </div>
  );
}

SpeakerView.propTypes = {
  activeSpeakerId: PropTypes.string,
  localVideoRef: PropTypes.object.isRequired,
  audioLevels: PropTypes.instanceOf(Map).isRequired,
  remoteStreams: PropTypes.instanceOf(Map).isRequired,
  isScreenSharing: PropTypes.bool,
};

function Thumbnail({
  username,
  stream,
  videoRef: externalVideoRef,
  isMirrored = false,
}) {
  const localVideoRef = useRef(null);

  useEffect(() => {
    const videoElement = externalVideoRef?.current || localVideoRef.current;
    if (videoElement && stream) {
      videoElement.srcObject = stream;
    }
  }, [stream, externalVideoRef]);

  return (
    <div className="shrink-0 w-32 h-24 relative bg-surface-variant rounded-2xl overflow-hidden cursor-pointer hover:ring-2 hover:ring-primary shadow-sm">
      {externalVideoRef ? (
        <video
          ref={externalVideoRef}
          autoPlay
          playsInline
          muted
          className={`w-full h-full object-cover ${isMirrored ? "mirror" : ""}`}
        />
      ) : (
        <video
          ref={localVideoRef}
          autoPlay
          playsInline
          className="w-full h-full object-cover"
        />
      )}
      <div className="absolute bottom-1 left-1 bg-surface/90 backdrop-blur-sm px-2 py-1 rounded-full text-on-surface text-xs truncate max-w-full">
        {username}
      </div>
    </div>
  );
}

Thumbnail.propTypes = {
  username: PropTypes.string.isRequired,
  stream: PropTypes.object,
  videoRef: PropTypes.object,
  isMirrored: PropTypes.bool,
};

function SidebarThumbnail({ username, stream, isActiveSpeaker, audioLevel }) {
  const videoRef = useRef(null);

  useEffect(() => {
    if (videoRef.current && stream) {
      videoRef.current.srcObject = stream;
      videoRef.current.play().catch(() => {
        // Browser may prevent autoplay - this is expected behavior
      });
    }
  }, [stream]);

  return (
    <div
      className={`relative bg-surface-variant rounded-2xl overflow-hidden aspect-video shrink-0 transition-all shadow-sm ${
        isActiveSpeaker ? "ring-2 ring-primary" : ""
      }`}
    >
      <video
        ref={videoRef}
        autoPlay
        playsInline
        className="w-full h-full object-cover"
      />
      <div className="absolute bottom-2 left-2 bg-surface/90 backdrop-blur-sm px-2 py-1 rounded-full text-on-surface text-xs flex items-center gap-1">
        <AudioLevelIndicator level={audioLevel} isSpeaking={isActiveSpeaker} />
        <span className="truncate max-w-[140px]">{username}</span>
      </div>
      {isActiveSpeaker && (
        <div className="absolute top-1 left-1 bg-primary text-on-primary px-1 py-0.5 rounded-full text-[10px] font-bold">
          SPEAKING
        </div>
      )}
    </div>
  );
}

SidebarThumbnail.propTypes = {
  username: PropTypes.string.isRequired,
  stream: PropTypes.object.isRequired,
  isActiveSpeaker: PropTypes.bool,
  audioLevel: PropTypes.number,
};
