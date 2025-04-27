// src/pages/index.tsx (or appropriate file path)

import React, { useState, useEffect, useCallback } from 'react';
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"; // Assuming Shadcn UI
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input"; // For interface name
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"; // For warnings
import { Terminal } from "lucide-react"; // Icon for alert

// Component Imports
import FileUploader from '@/components/FileUploader';
import ResultsDisplay from '@/components/ResultsDisplay'; // Default import
import FeaturesList from '@/components/FeaturesList';
import RealtimeResultsDisplay from '@/components/RealtimeResultsDisplay';

// Type Imports from Services
// ** CORRECTED: Import type for file results from the service file **
import { AnalysisResult as FileAnalysisResult } from '@/services/api'; // Adjust path if needed

// Realtime Service Functions and Types
import {
  connectRealtime,
  disconnectRealtime,
  startRealtimeCapture,
  stopRealtimeCapture,
  isRealtimeConnected,
  RealtimeResult
} from '@/services/realtimeService'; // Adjust path if needed

// Define the analysis mode type
type AnalysisMode = 'file' | 'realtime';

// Limit the number of real-time results stored in state to prevent memory issues
const MAX_REALTIME_RESULTS = 100;

const Index = () => {
  // Mode selection state
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>('file');

  // File Upload State
  const [fileResults, setFileResults] = useState<FileAnalysisResult | null>(null);
  const [isFileLoading, setIsFileLoading] = useState(false);

  // Real-time State
  const [isRealtimeConnectedState, setIsRealtimeConnectedState] = useState(false);
  const [isCapturing, setIsCapturing] = useState(false);
  const [realtimeResults, setRealtimeResults] = useState<RealtimeResult[]>([]);
  const [interfaceName, setInterfaceName] = useState<string>(''); // Optional interface input
  const [realtimeError, setRealtimeError] = useState<string | null>(null);

  // --- Callbacks for Real-time Events (Memoized with useCallback) ---

  const handleCaptureResult = useCallback((data: RealtimeResult) => {
    setRealtimeResults(prevResults => {
      const newResults = [data, ...prevResults];
      // Limit the number of results stored
      return newResults.slice(0, MAX_REALTIME_RESULTS);
    });
  }, []); // Empty dependency array: function reference is stable

  const handleCaptureError = useCallback((data: { error: string }) => {
    console.error("Received capture error:", data.error); // Log the specific error
    setRealtimeError(data.error); // Display error near controls
    setIsCapturing(false); // Ensure capturing state is turned off on error
  }, []); // Stable

  const handleCaptureStarted = useCallback(() => {
    console.log("Frontend: Capture Started event received.");
    setIsCapturing(true);
    setRealtimeError(null); // Clear previous errors
    setRealtimeResults([]); // Clear previous results on new start
  }, []); // Stable

  const handleCaptureStopped = useCallback(() => {
    console.log("Frontend: Capture Stopped event received.");
    setIsCapturing(false);
    // Optionally clear error on manual stop? Or keep it if it was an error stop?
    // setRealtimeError(null);
  }, []); // Stable

  // --- Effect for Managing Socket.IO Connection ---
  useEffect(() => {
    // Only run connection logic if in 'realtime' mode
    if (analysisMode === 'realtime') {
      console.log("Effect: Realtime mode selected, attempting connection...");
      // Attempt to connect and register listeners
      connectRealtime(
        // Service Status Listeners
        {
          onConnect: () => {
            console.log("Effect: Socket connected handler triggered.");
            setIsRealtimeConnectedState(true);
          },
          onDisconnect: () => {
            console.log("Effect: Socket disconnected handler triggered.");
            setIsRealtimeConnectedState(false);
            setIsCapturing(false); // Ensure capturing stops visually if disconnected
          },
          onConnectError: (err) => {
            console.error("Effect: Socket connection error handler triggered.", err);
            setIsRealtimeConnectedState(false);
          },
          onServerError: (data) => {
            console.error("Effect: Socket server error handler triggered.", data.error);
            setIsRealtimeConnectedState(false); // Treat server error as not connected for UI
          },
        },
        // Capture Event Listeners (pass the stable callbacks)
        {
          onCaptureResult: handleCaptureResult,
          onCaptureError: handleCaptureError,
          onCaptureStarted: handleCaptureStarted,
          onCaptureStopped: handleCaptureStopped,
        }
      );

      // ---- Cleanup Function ----
      // This runs when the component unmounts OR when dependencies change (analysisMode changes)
      return () => {
        console.log("Effect Cleanup: Switching mode or unmounting, ensuring disconnection...");
        // Check connection status before trying to stop/disconnect
        const connected = isRealtimeConnected();
        if (connected && isCapturing) {
          console.log("Effect Cleanup: Stopping active capture...");
          stopRealtimeCapture(); // Ask backend to stop
        }
        if (connected) {
          console.log("Effect Cleanup: Disconnecting socket...");
          disconnectRealtime();
        }
        // Reset state regardless
        setIsRealtimeConnectedState(false);
        setIsCapturing(false);
      };
    } else {
      // If switching *away* from real-time mode, ensure disconnection
      // This part handles the case when analysisMode changes from 'realtime' to 'file'
      console.log("Effect: Mode changed away from realtime, ensuring disconnection...");
      if (isRealtimeConnected()) {
        disconnectRealtime();
      }
      // Reset state related to realtime mode
      setIsRealtimeConnectedState(false);
      setIsCapturing(false);
      setRealtimeResults([]);
      setRealtimeError(null);
    }

    // --- ** CORRECTED DEPENDENCY ARRAY ** ---
    // This effect should re-run ONLY when the analysis mode changes,
    // or if the callback function references themselves change (which they won't due to useCallback).
  }, [analysisMode, handleCaptureResult, handleCaptureError, handleCaptureStarted, handleCaptureStopped]);
  // Removed `isCapturing` as changing capture status should NOT cause reconnect/disconnect

  // --- Button Click Handlers ---
  const handleStartCaptureClick = () => {
    // Check connection before trying to start
    if (!isCapturing && isRealtimeConnectedState) {
      console.log("UI: Start Capture button clicked.");
      setRealtimeResults([]); // Clear previous results visually
      setRealtimeError(null); // Clear previous errors visually
      startRealtimeCapture(interfaceName.trim() || null); // Pass trimmed interface name or null
    } else if (!isRealtimeConnectedState) {
      console.warn("UI: Start Capture clicked but not connected.");
      setRealtimeError("Cannot start capture: Not connected to the server.");
    }
  };

  const handleStopCaptureClick = () => {
    // Check connection and capturing state before trying to stop
    if (isCapturing && isRealtimeConnectedState) {
      console.log("UI: Stop Capture button clicked.");
      stopRealtimeCapture(); // Ask backend to stop
      // UI state (isCapturing) will be updated via the onCaptureStopped event handler
    } else {
      console.warn("UI: Stop Capture clicked but not capturing or not connected.");
    }
  };

  // --- Render Logic ---
  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl">
      {/* Title and Description */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-secondary mb-4">
          Network Intrusion Detection System
        </h1>
        <p className="text-xl text-slate-600 max-w-3xl mx-auto">
          Analyze network traffic via file upload or real-time capture to detect potential intrusions using machine learning.
        </p>
      </div>

      {/* Analysis Mode Selection Box */}
      <div className="bg-white rounded-xl shadow-md p-8 mb-12 border border-slate-100">
        <h2 className="text-2xl font-bold mb-6 text-center text-secondary">Select Analysis Mode</h2>
        {/* Radio Group for Mode Selection */}
        <RadioGroup
          defaultValue="file"
          value={analysisMode}
          onValueChange={(value: string) => setAnalysisMode(value as AnalysisMode)}
          className="flex justify-center gap-8 mb-6"
        >
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="file" id="mode-file" />
            <Label htmlFor="mode-file" className="text-lg cursor-pointer">File Upload</Label>
          </div>
          <div className="flex items-center space-x-2">
            <RadioGroupItem value="realtime" id="mode-realtime" />
            <Label htmlFor="mode-realtime" className="text-lg cursor-pointer">Real-Time Capture</Label>
          </div>
        </RadioGroup>

        {/* --- Conditional Rendering based on Mode --- */}

        {/* File Upload Section */}
        {analysisMode === 'file' && (
          <div>
            <h3 className="text-xl font-semibold mb-4 text-center text-slate-700">Upload Network Data File</h3>
            {isFileLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="w-16 h-16 border-4 border-slate-200 border-t-primary rounded-full animate-spin"></div>
                <p className="mt-4 text-slate-600">Analyzing file data...</p>
              </div>
            ) : (
              <FileUploader
                onResultsReceived={setFileResults}
                setIsLoading={setIsFileLoading}
              />
            )}
          </div>
        )}

        {/* Real-Time Capture Section */}
        {analysisMode === 'realtime' && (
          <div>
            <h3 className="text-xl font-semibold mb-4 text-center text-slate-700">Real-Time Network Capture</h3>
            {/* Warning Alert */}
            <Alert variant="destructive" className="mb-6">
              <Terminal className="h-4 w-4" />
              <AlertTitle>Important Notes & Requirements</AlertTitle>
              <AlertDescription>
                <ul className="list-disc list-inside space-y-1">
                  <li>Real-time capture requires the backend server to be run with <strong>root/administrator privileges</strong>.</li>
                  <li>The analysis performed is a <strong>simulation</strong> using the loaded model with simplified features derived from packets. It is <strong>not</strong> a fully accurate real-time IDS.</li>
                  <li>Ensure Scapy and required packet capture libraries (libpcap/Npcap) are installed correctly on the server.</li>
                  <li>Capturing on all interfaces (default) might require more resources. Specify an interface name if needed (e.g., Wi-Fi, Ethernet, eth0, en0).</li>
                </ul>
              </AlertDescription>
            </Alert>

            {/* Controls: Interface Input, Start/Stop Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-4">
              <Input
                type="text"
                placeholder="Network Interface (optional)"
                value={interfaceName}
                onChange={(e) => setInterfaceName(e.target.value)}
                className="max-w-xs"
                // Disable input if not connected or currently capturing
                disabled={isCapturing || !isRealtimeConnectedState}
              />
              <Button
                onClick={handleStartCaptureClick}
                // Disable start if already capturing or not connected
                disabled={isCapturing || !isRealtimeConnectedState}
                variant="secondary" // Or your preferred style
              >
                Start Capture
              </Button>
              <Button
                onClick={handleStopCaptureClick}
                // Disable stop if not capturing or not connected
                disabled={!isCapturing || !isRealtimeConnectedState}
                variant="destructive"
              >
                Stop Capture
              </Button>
            </div>

            {/* Status Indicator */}
            <div className="text-center mb-4 text-sm font-medium text-slate-600">
              Status: {isRealtimeConnectedState ? (isCapturing ? 'Capturing...' : 'Connected, Idle') : 'Disconnected'}
            </div>

            {/* Display Real-time Errors */}
            {realtimeError && (
              <Alert variant="destructive" className="mb-4">
                <AlertTitle>Capture Error</AlertTitle>
                <AlertDescription>{realtimeError}</AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </div> {/* End Mode Selection Box */}


      {/* --- Results Display Area --- */}

      {/* Display File Results */}
      {analysisMode === 'file' && fileResults && (
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6 text-center text-secondary">File Analysis Results</h2>
          <ResultsDisplay results={fileResults} />
        </div>
      )}

      {/* Display Real-Time Results */}
      {analysisMode === 'realtime' && (isRealtimeConnectedState || realtimeResults.length > 0) && (
        // Show the container even if connected but not yet capturing, or if showing old results after stopping
        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6 text-center text-secondary">Real-Time Analysis Stream</h2>
          <RealtimeResultsDisplay results={realtimeResults} />
        </div>
      )}

      {/* Features List Section */}
      <div className="bg-slate-50 rounded-xl p-8 border border-slate-200">
        <h2 className="text-2xl font-bold mb-6 text-center text-secondary">Model Input Features</h2>
        <p className="mb-6 text-center text-slate-600">
          The analysis (both file and simulated real-time) uses a model trained on the following features. For file uploads, ensure your CSV matches this structure (excluding 'attack').
        </p>
        <FeaturesList />
      </div>
    </div>
  );
};

export default Index;