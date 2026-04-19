import { useState, useEffect, useRef, useCallback } from "react";
import audioMonitor from "../services/audioMonitor";

export function useActiveSpeaker(participants, localStream, remoteStreams) {
  const [activeSpeakerId, setActiveSpeakerId] = useState(null);
  const [audioLevels, setAudioLevels] = useState(new Map());

  // PERF-001: Store audio levels in a ref to avoid state updates on every frame (~60fps × N users)
  const audioLevelsRef = useRef(new Map());
  const volumeHistory = useRef(new Map());

  // Speech detection threshold
  const SPEAKING_THRESHOLD = 15; // 0-100 scale
  const SPEAKING_DURATION = 500; // ms

  // PERF-001: Batch audio level and active speaker state updates every 100ms
  // instead of on every animation frame, reducing re-renders from ~300/s to 10/s
  useEffect(() => {
    const updateInterval = setInterval(() => {
      // Flush ref → state in a single batch
      setAudioLevels(new Map(audioLevelsRef.current));

      // Determine active speaker from ref data (no state dependency)
      let maxAvgVolume = 0;
      let speakerId = null;
      const now = Date.now();

      volumeHistory.current.forEach((history, userId) => {
        if (history.length === 0) return;

        const recentHistory = history.filter(
          (h) => now - h.timestamp < SPEAKING_DURATION
        );

        if (recentHistory.length === 0) return;

        const avgVolume =
          recentHistory.reduce((sum, h) => sum + h.volume, 0) /
          recentHistory.length;

        if (avgVolume > SPEAKING_THRESHOLD && avgVolume > maxAvgVolume) {
          maxAvgVolume = avgVolume;
          speakerId = userId;
        }
      });

      setActiveSpeakerId(speakerId);
    }, 100);

    return () => clearInterval(updateInterval);
  }, []);

  // PERF-001: updateVolume writes to ref only — no state updates, no re-renders
  const updateVolume = useCallback((userId, volume) => {
    audioLevelsRef.current.set(userId, volume);

    // Track volume history for stability
    if (!volumeHistory.current.has(userId)) {
      volumeHistory.current.set(userId, []);
    }

    const history = volumeHistory.current.get(userId);
    history.push({ volume, timestamp: Date.now() });

    // Keep only recent history (last 1 second)
    const recent = history.filter((h) => Date.now() - h.timestamp < 1000);
    volumeHistory.current.set(userId, recent);
  }, []);

  useEffect(() => {
    // Monitor local stream
    if (localStream) {
      audioMonitor.startMonitoring("local", localStream, (volume) => {
        updateVolume("local", volume);
      });
    }

    // Monitor remote streams
    remoteStreams.forEach(({ userId, stream }) => {
      audioMonitor.startMonitoring(userId, stream, (volume) => {
        updateVolume(userId, volume);
      });
    });

    // Clean up volumeHistory for departed users
    const currentIds = new Set([
      "local",
      ...remoteStreams.map((s) => s.userId),
    ]);
    volumeHistory.current.forEach((_, userId) => {
      if (!currentIds.has(userId)) {
        volumeHistory.current.delete(userId);
        audioLevelsRef.current.delete(userId);
      }
    });

    return () => {
      audioMonitor.stopAll(); // MEM-002: Cleanup is now async internally
    };
  }, [localStream, remoteStreams, updateVolume]);

  return { activeSpeakerId, audioLevels };
}
