class AudioMonitor {
  constructor() {
    this.audioContexts = new Map();
    this.analysers = new Map();
    this.animationFrames = new Map();
    this.volumeCallbacks = new Map();
  }

  startMonitoring(userId, stream, onVolumeChange) {
    // Stop existing monitoring for this user
    this.stopMonitoring(userId);

    try {
      const audioContext = new AudioContext();
      const analyser = audioContext.createAnalyser();
      analyser.fftSize = 256;
      analyser.smoothingTimeConstant = 0.3;

      const source = audioContext.createMediaStreamSource(stream);
      source.connect(analyser);

      this.audioContexts.set(userId, audioContext);
      this.analysers.set(userId, analyser);
      this.volumeCallbacks.set(userId, onVolumeChange);

      const dataArray = new Uint8Array(analyser.frequencyBinCount);

      const checkVolume = () => {
        if (!this.analysers.has(userId)) return;

        analyser.getByteFrequencyData(dataArray);

        let sum = 0;
        for (let i = 0; i < dataArray.length; i++) {
          sum += dataArray[i];
        }
        const average = sum / dataArray.length;
        const normalizedVolume = Math.min(average / 128, 1);

        const callback = this.volumeCallbacks.get(userId);
        if (callback) {
          callback(normalizedVolume);
        }

        const frameId = requestAnimationFrame(checkVolume);
        this.animationFrames.set(userId, frameId);
      };

      checkVolume();
    } catch (error) {
      console.error("Error starting audio monitoring:", error);
    }
  }

  // MEM-002: Properly close AudioContext — await the async close() and guard against double-close
  async stopMonitoring(userId) {
    const frameId = this.animationFrames.get(userId);
    if (frameId) {
      cancelAnimationFrame(frameId);
      this.animationFrames.delete(userId);
    }

    const audioContext = this.audioContexts.get(userId);
    if (audioContext && audioContext.state !== "closed") {
      try {
        await audioContext.close(); // MEM-002: Await the async close
      } catch (e) {
        // Already closed or in invalid state — safe to ignore
      }
      this.audioContexts.delete(userId);
    }

    this.analysers.delete(userId);
    this.volumeCallbacks.delete(userId);
  }

  // MEM-002: Stop all monitors concurrently and await completion
  async stopAll() {
    const userIds = Array.from(this.audioContexts.keys());
    await Promise.all(userIds.map((userId) => this.stopMonitoring(userId)));
  }
}

export default new AudioMonitor();
