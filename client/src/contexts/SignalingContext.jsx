import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
} from "react";
import { useAuth } from "./AuthContext";
import websocket from "../services/websocket";

const SignalingContext = createContext(null);

export const SignalingProvider = ({ children }) => {
  const { user, isAuthenticated } = useAuth();
  const [connectionState, setConnectionState] = useState("disconnected");
  const [currentRoom, setCurrentRoom] = useState(null);
  const [participants, setParticipants] = useState([]);

  // SEC-001: Connect WebSocket when authenticated — no localStorage token needed,
  // websocket.connect() internally fetches a short-lived ticket via httpOnly cookie
  useEffect(() => {
    if (isAuthenticated && user) {
      websocket.connect();
    } else {
      websocket.disconnect();
    }

    return () => {
      websocket.disconnect();
    };
  }, [isAuthenticated, user]);

  useEffect(() => {
    // ERR-001: Listen for connection state changes including reconnection metadata
    const unsubscribe = websocket.onConnectionStateChange((state, meta) => {
      setConnectionState(state);

      // ERR-001: Re-join room after WebSocket reconnection to restore signaling
      if (state === "connected" && meta?.reconnected && currentRoom) {
        console.log(
          "ERR-001: Reconnected — re-joining room:",
          currentRoom
        );
        websocket.send({
          type: "join-room",
          roomId: currentRoom,
          username: user?.displayName || user?.username,
        });
      }
    });

    return unsubscribe;
  }, [currentRoom, user]);

  useEffect(() => {
    const unsubscribeRoomJoined = websocket.on("room-joined", (message) => {
      setCurrentRoom(message.roomId);
      setParticipants(message.participants || []);
    });

    const unsubscribeUserJoined = websocket.on("user-joined", (message) => {
      setParticipants((prev) => [
        ...prev,
        {
          userId: message.userId,
          username: message.username,
        },
      ]);
    });

    const unsubscribeUserLeft = websocket.on("user-left", (message) => {
      setParticipants((prev) =>
        prev.filter((p) => p.userId !== message.userId)
      );
    });

    const unsubscribeRoomLeft = websocket.on("room-left", () => {
      setCurrentRoom(null);
      setParticipants([]);
    });

    return () => {
      unsubscribeRoomJoined();
      unsubscribeUserJoined();
      unsubscribeUserLeft();
      unsubscribeRoomLeft();
    };
  }, []);

  const joinRoom = useCallback((roomId, username) => {
    websocket.send({
      type: "join-room",
      roomId,
      username,
    });
  }, []);

  const leaveRoom = useCallback(() => {
    websocket.send({
      type: "leave-room",
    });
  }, []);

  const sendOffer = useCallback((targetUserId, offer) => {
    websocket.send({
      type: "offer",
      targetUserId,
      offer,
    });
  }, []);

  const sendAnswer = useCallback((targetUserId, answer) => {
    websocket.send({
      type: "answer",
      targetUserId,
      answer,
    });
  }, []);

  const sendIceCandidate = useCallback((targetUserId, candidate) => {
    websocket.send({
      type: "ice-candidate",
      targetUserId,
      candidate,
    });
  }, []);

  const sendMessage = useCallback((message) => {
    websocket.send(message);
  }, []);

  const onMessage = useCallback((messageType, handler) => {
    return websocket.on(messageType, handler);
  }, []);

  const value = {
    connectionState,
    currentRoom,
    participants,
    joinRoom,
    leaveRoom,
    sendOffer,
    sendAnswer,
    sendIceCandidate,
    sendMessage,
    onMessage,
    isConnected: connectionState === "connected",
  };

  return (
    <SignalingContext.Provider value={value}>
      {children}
    </SignalingContext.Provider>
  );
};

export const useSignaling = () => {
  const context = useContext(SignalingContext);
  if (!context) {
    throw new Error("useSignaling must be used within SignalingProvider");
  }
  return context;
};
