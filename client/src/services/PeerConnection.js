import { RTC_CONFIG } from "../config/webrtc";

class PeerConnection {
  constructor(userId, username, signaling, onTrack, onConnectionStateChange) {
    this.userId = userId;
    this.username = username;
    this.signaling = signaling;
    this.onTrackCallback = onTrack;
    this.onConnectionStateChangeCallback = onConnectionStateChange;

    this.pc = new RTCPeerConnection(RTC_CONFIG);
    this.iceCandidateQueue = [];
    this.restartAttempts = 0;
    this.maxRestartAttempts = 3;
    this.isRestarting = false;
    this.connectionFailedTimeout = null;

    this.setupEventHandlers();
  }

  setupEventHandlers() {
    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        console.log("Sending ICE candidate to", this.userId);
        this.signaling.sendIceCandidate(this.userId, event.candidate);
      }
    };

    this.pc.ontrack = (event) => {
      console.log("Received remote track from", this.userId);
      if (this.onTrackCallback) {
        this.onTrackCallback(event.streams[0]);
      }
    };

    this.pc.onconnectionstatechange = () => {
      console.log(
        "Connection state with",
        this.userId,
        ":",
        this.pc.connectionState
      );

      // Clear any existing timeout
      if (this.connectionFailedTimeout) {
        clearTimeout(this.connectionFailedTimeout);
        this.connectionFailedTimeout = null;
      }

      if (this.onConnectionStateChangeCallback) {
        this.onConnectionStateChangeCallback(this.pc.connectionState);
      }

      // Handle connection failures with ICE restart
      if (this.pc.connectionState === "failed") {
        this.handleConnectionFailed();
      } else if (this.pc.connectionState === "connected") {
        // Reset restart attempts on successful connection
        this.restartAttempts = 0;
        this.isRestarting = false;
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      console.log(
        "ICE connection state with",
        this.userId,
        ":",
        this.pc.iceConnectionState
      );

      // Handle disconnected state with a delay before restart
      if (this.pc.iceConnectionState === "disconnected") {
        this.connectionFailedTimeout = setTimeout(() => {
          if (
            this.pc.iceConnectionState === "disconnected" &&
            !this.isRestarting
          ) {
            console.log("ICE still disconnected, attempting restart...");
            this.handleConnectionFailed();
          }
        }, 5000); // Wait 5 seconds before restart
      } else if (
        this.pc.iceConnectionState === "connected" ||
        this.pc.iceConnectionState === "completed"
      ) {
        // Clear timeout if connection recovers
        if (this.connectionFailedTimeout) {
          clearTimeout(this.connectionFailedTimeout);
          this.connectionFailedTimeout = null;
        }
      }
    };

    this.pc.onicegatheringstatechange = () => {
      console.log(
        "ICE gathering state with",
        this.userId,
        ":",
        this.pc.iceGatheringState
      );
    };

    // Add this new handler
    this.pc.onnegotiationneeded = async () => {
      console.log("Negotiation needed with", this.userId);
      // This will be handled by the offer/answer flow
    };
  }

  // RTC-003: ICE restart with exponential backoff to prevent flooding the signaling channel
  async handleConnectionFailed() {
    if (this.isRestarting) {
      console.log("Already restarting connection with", this.userId);
      return;
    }

    if (this.restartAttempts >= this.maxRestartAttempts) {
      console.error(
        "Max ICE restart attempts reached for",
        this.userId,
        "- closing connection"
      );

      // Clear timeout before giving up
      if (this.connectionFailedTimeout) {
        clearTimeout(this.connectionFailedTimeout);
        this.connectionFailedTimeout = null;
      }

      if (this.onConnectionStateChangeCallback) {
        this.onConnectionStateChangeCallback("closed");
      }
      return;
    }

    this.isRestarting = true;
    this.restartAttempts++;

    // RTC-003: Exponential backoff — 1s, 2s, 4s instead of immediate rapid-fire restarts
    const delay = Math.min(
      1000 * Math.pow(2, this.restartAttempts - 1),
      8000
    );
    console.log(
      `ICE restart for ${this.userId} in ${delay}ms (attempt ${this.restartAttempts}/${this.maxRestartAttempts})`
    );

    await new Promise((resolve) => setTimeout(resolve, delay));

    // RTC-003: Check if connection recovered during the backoff wait
    if (
      this.pc.connectionState === "connected" ||
      this.pc.iceConnectionState === "connected" ||
      this.pc.iceConnectionState === "completed"
    ) {
      console.log("Connection recovered during backoff, skipping restart");
      this.isRestarting = false;
      return;
    }

    try {
      // Perform ICE restart by creating a new offer with iceRestart
      const offer = await this.pc.createOffer({ iceRestart: true });
      await this.pc.setLocalDescription(offer);

      // Send the new offer to the peer
      this.signaling.sendOffer(this.userId, offer);

      console.log("ICE restart offer sent to", this.userId);
    } catch (error) {
      console.error("Error during ICE restart:", error);
      this.isRestarting = false;

      // Clear timeout on error
      if (this.connectionFailedTimeout) {
        clearTimeout(this.connectionFailedTimeout);
        this.connectionFailedTimeout = null;
      }
    }
  }

  // Add this new method to set bandwidth limits
  async setBandwidth(maxBitrate = 2500) {
    const senders = this.pc.getSenders();

    for (const sender of senders) {
      if (!sender.track || sender.track.kind !== "video") continue;

      const parameters = sender.getParameters();

      if (!parameters.encodings) {
        parameters.encodings = [{}];
      }

      parameters.encodings[0].maxBitrate = maxBitrate * 1000; // Convert to bps

      // Add degradation preference for constrained networks
      if (parameters.degradationPreference === undefined) {
        parameters.degradationPreference = "maintain-framerate";
      }

      try {
        await sender.setParameters(parameters);
        console.log(`Set max bitrate to ${maxBitrate}kbps for`, this.userId);
      } catch (error) {
        console.error("Error setting bandwidth:", error);
      }
    }
  }

  // Get connection statistics
  async getStats() {
    try {
      const stats = await this.pc.getStats();
      const result = {
        video: { bitrate: 0, packetsLost: 0, jitter: 0, rtt: 0 },
        audio: { bitrate: 0, packetsLost: 0, jitter: 0, rtt: 0 },
      };

      stats.forEach((report) => {
        if (report.type === "inbound-rtp") {
          const kind = report.kind || report.mediaType;
          if (result[kind]) {
            result[kind].packetsLost = report.packetsLost || 0;
            result[kind].jitter = report.jitter || 0;
            result[kind].bitrate = report.bytesReceived
              ? (report.bytesReceived * 8) / (report.timestamp / 1000)
              : 0;
          }
        } else if (
          report.type === "candidate-pair" &&
          report.state === "succeeded"
        ) {
          result.video.rtt = report.currentRoundTripTime || 0;
          result.audio.rtt = report.currentRoundTripTime || 0;
        }
      });

      return result;
    } catch (error) {
      console.error("Error getting stats:", error);
      return null;
    }
  }

  addLocalStream(stream) {
    console.log("Adding local stream to peer connection with", this.userId);
    stream.getTracks().forEach((track) => {
      this.pc.addTrack(track, stream);
    });
  }

  async createOffer() {
    try {
      console.log("Creating offer for", this.userId);
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);
      return offer;
    } catch (error) {
      console.error("Error creating offer:", error);
      throw error;
    }
  }

  async createAnswer() {
    try {
      console.log("Creating answer for", this.userId);
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      return answer;
    } catch (error) {
      console.error("Error creating answer:", error);
      throw error;
    }
  }

  async setRemoteDescription(description) {
    try {
      console.log("Setting remote description from", this.userId);
      await this.pc.setRemoteDescription(
        new RTCSessionDescription(description)
      );

      // Process queued ICE candidates
      while (this.iceCandidateQueue.length > 0) {
        const candidate = this.iceCandidateQueue.shift();
        await this.addIceCandidate(candidate);
      }
    } catch (error) {
      console.error("Error setting remote description:", error);
      throw error;
    }
  }

  async addIceCandidate(candidate) {
    try {
      if (this.pc.remoteDescription) {
        await this.pc.addIceCandidate(new RTCIceCandidate(candidate));
        console.log("Added ICE candidate from", this.userId);
      } else {
        console.log("Queuing ICE candidate from", this.userId);
        this.iceCandidateQueue.push(candidate);
      }
    } catch (error) {
      console.error("Error adding ICE candidate:", error);
    }
  }

  // MEM-003: Properly close peer connection — stop remote tracks and remove event handlers
  close() {
    console.log("Closing peer connection with", this.userId);

    // Clear any pending timeouts
    if (this.connectionFailedTimeout) {
      clearTimeout(this.connectionFailedTimeout);
      this.connectionFailedTimeout = null;
    }

    // MEM-003: Remove all event handlers to prevent callbacks on closed connection
    this.pc.onicecandidate = null;
    this.pc.ontrack = null;
    this.pc.onconnectionstatechange = null;
    this.pc.oniceconnectionstatechange = null;
    this.pc.onicegatheringstatechange = null;
    this.pc.onnegotiationneeded = null;

    // MEM-003: Stop all received tracks to release the media pipeline
    this.pc.getReceivers().forEach((receiver) => {
      if (receiver.track) {
        receiver.track.stop();
      }
    });

    this.pc.close();

    // MEM-003: Null out callbacks to prevent stale references
    this.onTrackCallback = null;
    this.onConnectionStateChangeCallback = null;
  }

  getConnectionState() {
    return this.pc.connectionState;
  }

  getIceConnectionState() {
    return this.pc.iceConnectionState;
  }
}

export default PeerConnection;
