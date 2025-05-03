// src/services/realtimeService.ts
import { io, Socket } from "socket.io-client";
import { toast } from "sonner";

const SOCKET_SERVER_URL = "http://localhost:5000"; // Your Flask-SocketIO server URL

let socket: Socket | null = null;

// --- UPDATED INTERFACE ---
export interface RealtimeResult {
  prediction: string;          // Prediction from the primary signature model
  anomaly_prediction: string | null; // Prediction from the secondary anomaly model (or null/string indicator)
  packet_summary: string;
  timestamp: number;
}
// -------------------------

interface ServiceStatusListeners {
  onConnect?: () => void;
  onDisconnect?: () => void;
  onConnectError?: (err: Error) => void;
  onServerError?: (data: { error: string }) => void;
}

interface CaptureListeners {
  onCaptureResult?: (data: RealtimeResult) => void; // Type uses the updated interface
  onCaptureError?: (data: { error: string }) => void;
  onCaptureStarted?: (data: { message: string }) => void;
  onCaptureStopped?: (data: { message: string }) => void;
}

export const connectRealtime = (
  serviceListeners: ServiceStatusListeners,
  captureListeners: CaptureListeners
): Socket | null => {
  if (socket && socket.connected) {
    console.log("Socket already connected.");
    return socket;
  }

  console.log("Attempting to connect to Socket.IO server...");
  socket = io(SOCKET_SERVER_URL, {
    reconnectionAttempts: 3,
    timeout: 5000,
  });

  // --- Service Status Listeners (No changes needed here) ---
  socket.on("connect", () => {
    console.log("Socket connected:", socket?.id);
    toast.success("Connected to real-time analysis server.");
    serviceListeners.onConnect?.();
  });

  socket.on("disconnect", (reason) => {
    console.log("Socket disconnected:", reason);
    if (reason !== "io client disconnect") {
      toast.warning("Disconnected from real-time server.");
    }
    serviceListeners.onDisconnect?.();
    if (reason === "io server disconnect" || reason === "transport close") {
      socket?.removeAllListeners();
      socket = null;
    }
  });

  socket.on("connect_error", (err) => {
    console.error("Socket connection error:", err);
    toast.error(`Connection error: ${err.message}`);
    serviceListeners.onConnectError?.(err);
    socket?.disconnect();
    socket = null;
  });

  socket.on("server_error", (data: { error: string }) => {
    console.error("Server reported error on connect:", data.error);
    toast.error(`Server error: ${data.error}`);
    serviceListeners.onServerError?.(data);
  });

  // --- Capture Event Listeners ---
  // The 'capture_result' listener now expects data matching the updated RealtimeResult interface
  socket.on("capture_result", (data: RealtimeResult) => {
    // console.log('Capture Result:', data); // Includes both predictions now
    captureListeners.onCaptureResult?.(data);
  });

  socket.on("capture_error", (data: { error: string }) => {
    console.error("Capture Error:", data.error);
    toast.error(`Capture error: ${data.error}`);
    captureListeners.onCaptureError?.(data);
  });

  socket.on("capture_started", (data: { message: string }) => {
    console.log("Capture Started:", data.message);
    toast.info(data.message);
    captureListeners.onCaptureStarted?.(data);
  });

  socket.on("capture_stopped", (data: { message: string }) => {
    console.log("Capture Stopped:", data.message);
    toast.info(data.message);
    captureListeners.onCaptureStopped?.(data);
  });

  return socket;
};

// --- disconnectRealtime, startRealtimeCapture, stopRealtimeCapture, isRealtimeConnected ---
// --- remain unchanged ---

export const disconnectRealtime = () => {
  if (socket?.connected) {
    console.log("Disconnecting socket...");
    socket.disconnect();
    socket = null;
    toast.info("Disconnected from real-time analysis.");
  } else {
    console.log("Socket already disconnected or not initialized.");
  }
};

export const startRealtimeCapture = (interfaceName?: string | null) => {
  if (socket?.connected) {
    console.log(`Sending start_capture signal for interface: ${interfaceName || "all"}`);
    socket.emit("start_capture", { interface: interfaceName });
  } else {
    console.error("Socket not connected. Cannot start capture.");
    toast.error("Not connected to server. Cannot start capture.");
  }
};

export const stopRealtimeCapture = () => {
  if (socket?.connected) {
    console.log("Sending stop_capture signal");
    socket.emit("stop_capture");
  } else {
    console.error("Socket not connected. Cannot stop capture.");
  }
};

export const isRealtimeConnected = (): boolean => {
  return socket?.connected ?? false;
};