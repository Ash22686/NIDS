
import React from 'react';
import { AlertTriangle, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
// At the top of Index.tsx, ensure this matches your file analysis result type

interface ResultsDisplayProps {
  results: {
    prediction: string;
    confidence?: number;
    details?: {
      [key: string]: any;
    };
  } | null;
}

const ResultsDisplay = ({ results }: ResultsDisplayProps) => {
  if (!results) {
    return null;
  }

  const isNormal = results.prediction === 'Normal';
  const getStatusColor = () => {
    switch (results.prediction) {
      case 'Normal':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'DoS':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'Probe':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'R2L':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'U2R':
        return 'bg-purple-100 text-purple-800 border-purple-200';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-200';
    }
  };

  const getDescriptionByType = () => {
    switch (results.prediction) {
      case 'Normal':
        return 'No malicious activity detected in the network traffic.';
      case 'DoS':
        return 'Denial of Service attack detected - attempt to make network resources unavailable.';
      case 'Probe':
        return 'Network scanning or reconnaissance activity detected.';
      case 'R2L':
        return 'Remote to Local attack detected - unauthorized access from remote machine.';
      case 'U2R':
        return 'User to Root attack detected - unauthorized escalation of privilege.';
      default:
        return 'Analysis complete.';
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <Card className={cn("border-2", isNormal ? "border-green-200" : "border-red-200")}>
        <CardHeader className={cn("pb-2", isNormal ? "text-green-800" : "text-red-800")}>
          <CardTitle className="flex items-center gap-2 text-2xl">
            {isNormal ? (
              <Check className="h-6 w-6 text-green-600" />
            ) : (
              <AlertTriangle className="h-6 w-6 text-red-600" />
            )}
            Traffic Analysis Results
          </CardTitle>
          <CardDescription>
            Analysis completed {new Date().toLocaleTimeString()}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mt-4 space-y-4">
            <div className="flex items-center">
              <span className="text-sm font-medium text-slate-500 w-32">Classification:</span>
              <span className={cn("px-3 py-1 rounded-full text-sm font-medium", getStatusColor())}>
                {results.prediction}
              </span>
            </div>
            
            {results.confidence !== undefined && (
              <div className="flex items-center">
                <span className="text-sm font-medium text-slate-500 w-32">Confidence:</span>
                <div className="flex items-center gap-2">
                  <div className="bg-slate-200 h-2 w-40 rounded-full overflow-hidden">
                    <div 
                      className={cn(
                        "h-full rounded-full", 
                        isNormal ? "bg-green-500" : "bg-red-500"
                      )}
                      style={{ width: `${results.confidence * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-sm">{Math.round(results.confidence * 100)}%</span>
                </div>
              </div>
            )}
            
            <div className="mt-6 p-4 rounded-lg bg-slate-50">
              <h3 className="font-medium text-slate-800 mb-2">Analysis Details</h3>
              <p className="text-sm text-slate-600">{getDescriptionByType()}</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ResultsDisplay;
