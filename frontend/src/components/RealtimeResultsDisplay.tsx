// src/components/RealtimeResultsDisplay.tsx
import React from "react";
import { RealtimeResult } from "@/services/realtimeService"; // Import the type
import { ScrollArea } from "@/components/ui/scroll-area"; // Assuming Shadcn UI
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

  const getBadgeVariant = (
    prediction: string
  ): "default" | "destructive" | "secondary" | "outline" => {
    if (prediction === "Normal") return "default"; // Or 'secondary'
    if (
      prediction.includes("DOS") ||
      prediction.includes("U2R") ||
      prediction.includes("R2L")
    )
      return "destructive";
    if (prediction.includes("PROBE")) return "outline";
    return "secondary";
  };

  return (
  <ScrollArea className="h-[400px] w-full rounded-md border p-4 bg-white shadow-sm">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-[180px]">Timestamp</TableHead>
          <TableHead>Packet Summary</TableHead>
          <TableHead className="text-right">Prediction</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {results.map((result, index) => (
          <TableRow key={`${result.timestamp}-${index}`}>
            <TableCell className="font-mono text-xs">
              {new Date(result.timestamp * 1000).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false,
              })}
              .
              {String(new Date(result.timestamp * 1000).getMilliseconds()).padStart(3, "0")}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {result.packet_summary}
            </TableCell>
            <TableCell className="text-right">
              <Badge variant={getBadgeVariant(result.prediction)}>
                {result.prediction}
              </Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  </ScrollArea>
)};

export default RealtimeResultsDisplay;