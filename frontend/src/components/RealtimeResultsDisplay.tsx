// src/components/RealtimeResultsDisplay.tsx
import React from "react";
import { RealtimeResult } from "@/services/realtimeService"; // Import the updated type
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge"; // For prediction badge

interface RealtimeResultsDisplayProps {
  results: RealtimeResult[];
}

const RealtimeResultsDisplay: React.FC<RealtimeResultsDisplayProps> = ({
  results,
}) => {
  if (!results || results.length === 0) {
    return (
      <p className="text-center text-slate-500 mt-4">
        Waiting for real-time data...
      </p>
    );
  }

  // Function to determine the variant for the primary prediction badge
  const getBadgeVariant = (
    prediction: string
  ): "default" | "destructive" | "secondary" | "outline" => {
    // Handle potential errors/unknowns first
    if (prediction.toLowerCase().includes("error") || prediction.toLowerCase().includes("unknown")) {
        return "secondary";
    }
    if (prediction === "Normal") return "default"; // Use default (often green/blue in themes) for Normal
    if (
      prediction.includes("DOS") ||
      prediction.includes("U2R") ||
      prediction.includes("R2L")
    )
      return "destructive"; // Red for definite attacks
    if (prediction.includes("PROBE")) return "outline"; // Different style for probing
    return "secondary"; // Fallback
  };

  // Function to determine the text color for the anomaly prediction
  const getAnomalyTextColor = (anomalyPrediction: string | null): string => {
    if (!anomalyPrediction) return ""; // No text if null

    // Match backend strings (adjust if your backend sends different strings)
    if (anomalyPrediction.toLowerCase().includes("anomalous")) {
      return "text-red-600"; // Red for detected anomalies
    }
    if (anomalyPrediction.toLowerCase().includes("error")) {
      return "text-orange-600"; // Orange for errors during anomaly check
    }
    if (anomalyPrediction.toLowerCase().includes("n/a")) {
        return "text-slate-400"; // Lighter grey for N/A
    }
    // Default for "Normal (Anomaly Model)" or other non-threatening statuses
    return "text-slate-500";
  };


  return (
    // Using ScrollArea for potentially long lists
    <ScrollArea className="h-[400px] w-full rounded-md border p-4 bg-white shadow-sm">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[180px]">Timestamp</TableHead>
            <TableHead>Packet Summary</TableHead>
            {/* Adjusted Header Text */}
            <TableHead className="text-right">Detection Result</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {/* Map over results, ensuring a unique key */}
          {results.map((result, index) => (
            <TableRow key={`${result.timestamp}-${index}-${result.packet_summary}`}> {/* More robust key */}
              <TableCell className="font-mono text-xs">
                {/* Formatting timestamp with milliseconds */}
                {new Date(result.timestamp * 1000).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                  hour12: false, // Use 24-hour format
                })}
                .
                {String(
                  new Date(result.timestamp * 1000).getMilliseconds()
                ).padStart(3, "0")}
              </TableCell>
              <TableCell className="font-mono text-xs whitespace-nowrap overflow-hidden text-ellipsis max-w-[300px] sm:max-w-none"> {/* Prevent long summaries breaking layout */}
                {result.packet_summary}
              </TableCell>
              <TableCell className="text-right align-top"> {/* Align content top if text wraps */}
                {/* Primary Prediction Badge */}
                <Badge variant={getBadgeVariant(result.prediction)} className="mr-2">
                  {result.prediction}
                </Badge>

                {/* Conditionally Display Anomaly Prediction */}
                {result.anomaly_prediction && ( // Only render if anomaly_prediction is not null/empty
                  <span
                    className={`italic text-xs ${getAnomalyTextColor(result.anomaly_prediction)}`}
                  >
                    ({result.anomaly_prediction}) {/* Display text in parentheses */}
                  </span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </ScrollArea>
  );
};

export default RealtimeResultsDisplay;