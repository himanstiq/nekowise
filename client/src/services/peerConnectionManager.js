import PeerConnection from "./PeerConnection";
import mediaService from "./mediaService";

class PeerConnectionManager {
  constructor() {
    this.peers = new Map();
    this.signaling = null;
    this.localUserId = null; // RTC-001: Used for glare condition resolution
    this.onRemoteStreamCallback = null;
    this.onPeerConnectionStateCallback = null;
  }

  // RTC-001: Accept localUserId for polite/impolite peer determination
  initialize(signaling, localUserId, onRemoteStream, onPeerConnectionState) {
    this.signaling = signaling;
    this.localUserId = localUserId; // RTC-001: Store local user ID
    this.onRemoteStreamCallback = onRemoteStream;
    this.onPeerConnectionStateCallback = onPeerConnectionState;

    this.setupSignalingHandlers();
  }

  setupSignalingHandlers() {
    // Use the signaling context's onMessage method
    this.signaling.onMessage("offer", async (message) => {
      await this.handleOffer(message);
    });

    this.signaling.onMessage("answer", async (message) => {
      await this.handleAnswer(message);
    });

    this.signaling.onMessage("ice-candidate", async (message) => {
      await this.handleIceCandidate(message);
    });

    this.signaling.onMessage("user-left", (message) => {
      this.removePeer(message.userId);
    });
  }

  async createPeerConnection(userId, username) {
    if (this.peers.has(userId)) {
      console.log("Peer connection already exists for", userId);
      return this.peers.get(userId);
    }

    console.log("Creating peer connection for", userId, username);

    const pc = new PeerConnection(
      userId,
      username,
      this.signaling,
      (stream) => {
        if (this.onRemoteStreamCallback) {
          this.onRemoteStreamCallback(userId, username, stream);
        }
      },
      (state) => {
        if (this.onPeerConnectionStateCallback) {
          this.onPeerConnectionStateCallback(userId, state);
        }

        if (state === "failed" || state === "closed") {
          this.removePeer(userId);
        }
      }
    );

    const localStream = mediaService.getLocalStream();
    if (localStream) {
      pc.addLocalStream(localStream);
    }

    this.peers.set(userId, pc);
    return pc;
  }

  async createOffer(userId, username) {
    try {
      console.log("Creating offer for", userId, username);
      const pc = await this.createPeerConnection(userId, username);
      const offer = await pc.createOffer();

      this.signaling.sendOffer(userId, offer);
      console.log("Offer sent to", userId);
    } catch (error) {
      console.error("Error creating offer for", userId, error);
    }
  }

  // RTC-001: Handle incoming offers with perfect negotiation pattern (glare resolution)
  async handleOffer(message) {
    try {
      const { fromUserId, fromUsername, offer } = message;
      console.log("Received offer from", fromUserId, fromUsername);

      const pc = await this.createPeerConnection(fromUserId, fromUsername);

      // RTC-001: Check signaling state — handle glare (simultaneous offers)
      const signalingState = pc.pc.signalingState;
      if (signalingState !== "stable") {
        // RTC-001: Polite/impolite peer pattern — lower ID is "polite" and yields
        const isPolite = this.localUserId < fromUserId;

        if (!isPolite) {
          // Impolite peer: ignore incoming offer, keep our own
          console.log(
            `RTC-001: Ignoring offer from ${fromUserId} — we are impolite peer (state: ${signalingState})`
          );
          return;
        }

        // Polite peer: rollback our offer and accept theirs
        console.log(
          `RTC-001: Rolling back local offer for ${fromUserId} — we are polite peer`
        );
        await pc.pc.setLocalDescription({ type: "rollback" });
      }

      await pc.setRemoteDescription(offer);

      const answer = await pc.createAnswer();
      this.signaling.sendAnswer(fromUserId, answer);

      console.log("Answer sent to", fromUserId);
    } catch (error) {
      console.error("Error handling offer:", error);
    }
  }

  async handleAnswer(message) {
    try {
      const { fromUserId, answer } = message;
      console.log("Received answer from", fromUserId);

      const pc = this.peers.get(fromUserId);
      if (!pc) {
        console.warn("No peer connection found for", fromUserId);
        return;
      }

      // Check if we're in the correct state to receive an answer
      const signalingState = pc.pc.signalingState;
      if (signalingState !== "have-local-offer") {
        console.warn(
          `Ignoring answer from ${fromUserId} - wrong signaling state: ${signalingState} (expected: have-local-offer)`
        );
        return;
      }

      await pc.setRemoteDescription(answer);
    } catch (error) {
      console.error("Error handling answer:", error);
    }
  }

  async handleIceCandidate(message) {
    try {
      const { fromUserId, candidate } = message;
      console.log("Received ICE candidate from", fromUserId);

      const pc = this.peers.get(fromUserId);
      if (pc) {
        await pc.addIceCandidate(candidate);
      } else {
        console.warn("No peer connection found for", fromUserId);
      }
    } catch (error) {
      console.error("Error handling ICE candidate:", error);
    }
  }

  removePeer(userId) {
    const pc = this.peers.get(userId);
    if (pc) {
      pc.close();
      this.peers.delete(userId);
      console.log("Removed peer connection for", userId);
    }
  }

  closeAllConnections() {
    console.log("Closing all peer connections");
    this.peers.forEach((pc) => pc.close());
    this.peers.clear();
  }

  getPeer(userId) {
    return this.peers.get(userId);
  }

  getAllPeers() {
    return Array.from(this.peers.values());
  }
}

export default new PeerConnectionManager();
