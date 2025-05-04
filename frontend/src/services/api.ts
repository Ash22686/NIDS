// src/services/api.ts
import { toast } from "sonner";

// Ensure this matches the host and port where your Flask backend is running
const API_ENDPOINT = "http://localhost:5000/api/analyze";

// Type for the backend response (success case)
interface AnalysisSummaryResponse {
  summary: { [key: string]: number }; // e.g., { "Normal": 150, "DoS": 20 }
  total_rows: number; // Rows *received* and attempted by backend
  processed_rows: number; // Rows successfully processed by backend
  error_rows: number; // Rows skipped due to errors by backend
  error_preview?: string[]; // Optional: First few error messages from backend
}

// Type for the backend response (error case)
interface AnalysisErrorResponse {
  error: string;
}

// Type for the data structure returned to the UI component
// Added optional 'analysisNote'
export interface AnalysisSummaryResult {
  summary: { [key: string]: number };
  totalRows: number; // Corresponds to backend's total_rows (rows *sent*)
  processedRows: number; // Corresponds to backend's processed_rows
  errorRows: number; // Corresponds to backend's error_rows
  errorPreview?: string[]; // Optional field for UI display
  fileName: string; // Original full file name
  fileSize: number; // Original full file size
  timestamp: string; // ISO string format
  analysisNote?: string; // Note about partial analysis
}

// --- Helper Function to read file content as text ---
// Reads the WHOLE file content
const readFileAsText = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        resolve(reader.result); // Resolve with the entire file content
      } else {
        reject(new Error("Failed to read file as text."));
      }
    };
    reader.onerror = () => {
      reject(reader.error || new Error("File reading error."));
    };
    reader.readAsText(file); // Read the file content
  });
};

// --- Main File Analysis Function ---
/**
 * Reads the file content, slices it to a maximum number of rows, sends the subset
 * to the analysis API, and returns the aggregated summary result for that subset.
 * @param file The file object to analyze.
 * @returns A promise that resolves with the AnalysisSummaryResult or rejects with an error.
 */
export const analyzeFile = async (
  file: File
): Promise<AnalysisSummaryResult> => {
  console.log(
    "Attempting to analyze file via API (subset mode):",
    file.name,
    file.type,
    file.size
  );

  // --- Configuration for slicing ---
  const MAX_ROWS_TO_SEND = 100; // Set the desired number of rows for testing
  // ----------------------------------------

  try {
    // 1. Read the *entire* file content first
    const fullCsvString = await readFileAsText(file);
    console.log(`Read full file content, length: ${fullCsvString.length}`);

    if (!fullCsvString.trim()) {
      toast.error("File appears to be empty or could not be read.");
      throw new Error("File content is empty.");
    }

    // --- Slice the data to send only the first N rows ---
    const lines = fullCsvString.split("\n");
    const numRowsToSend = Math.min(lines.length, MAX_ROWS_TO_SEND); // Handle files smaller than N
    // Filter out potentially empty lines that might result from splitting or trailing newlines
    const linesToSend = lines
      .slice(0, numRowsToSend)
      .filter((line) => line.trim() !== "");
    const csvDataToSend = linesToSend.join("\n"); // Join back only the selected lines

    if (linesToSend.length === 0) {
      toast.error(
        `The first ${MAX_ROWS_TO_SEND} lines of the file appear to be empty.`
      );
      throw new Error(`First ${MAX_ROWS_TO_SEND} lines are empty.`);
    }

    console.log(
      `Read ${lines.length} total lines from file. Sending first ${linesToSend.length} non-empty line(s) (up to ${MAX_ROWS_TO_SEND}).`
    );
    console.log(
      "Sliced CSV data for API (first 100 chars):",
      csvDataToSend.substring(0, 100) + "..."
    );
    // -------------------------------------------------------------

    // 2. Send the *SLICED* content to the backend API endpoint
    console.log(
      `Sending POST request to ${API_ENDPOINT} with ${linesToSend.length} rows.`
    );
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Add other headers if needed
      },
      // --- Use the sliced data ---
      body: JSON.stringify({ csv_data: csvDataToSend }),
      // ---------------------------
    });
    console.log(`Received response with status: ${response.status}`);

    // 3. Handle the response (both success and error)
    let responseData;
    try {
      responseData = await response.json(); // Attempt to parse JSON
    } catch (parseError) {
      console.error("Could not parse response JSON:", parseError);
      if (!response.ok) {
        throw new Error(
          `API request failed with HTTP ${response.status}: ${response.statusText}. Response body was not valid JSON.`
        );
      }
      throw new Error(
        "Received an OK response, but failed to parse JSON body."
      );
    }

    if (!response.ok) {
      const errorMessage =
        (responseData as AnalysisErrorResponse)?.error ||
        `Analysis failed (HTTP ${response.status}): ${response.statusText}. Check server logs.`;
      console.error(
        "Backend returned error:",
        errorMessage,
        "Full response:",
        responseData
      );
      toast.error(`Analysis failed: ${errorMessage}`);
      throw new Error(`API request failed: ${errorMessage}`);
    }

    // 4. Process the successful JSON response (Summary for the subset)
    const result = responseData as AnalysisSummaryResponse;
    console.log("API Success Response (Summary for subset):", result);

    // Basic validation of the summary response structure
    if (
      result === null ||
      typeof result !== "object" ||
      typeof result.summary !== "object" ||
      typeof result.total_rows !== "number"
    ) {
      console.error("Invalid summary response format from API:", result);
      toast.error("Received an invalid summary response from the server.");
      throw new Error("Invalid API summary response format.");
    }

    // 5. Return the data structure expected by the UI
    const analysisNote = `Analysis performed on the first ${linesToSend.length} non-empty row(s) of the file.`;
    const finalResult: AnalysisSummaryResult = {
      summary: result.summary,
      totalRows: result.total_rows, // Rows backend received/attempted from subset
      processedRows: result.processed_rows, // Rows backend processed from subset
      errorRows: result.error_rows, // Rows backend skipped from subset
      errorPreview: result.error_preview,
      fileName: file.name, // Keep original file info
      fileSize: file.size, // Keep original file info
      timestamp: new Date().toISOString(),
      analysisNote: analysisNote, // Add the note
    };
    console.log(
      "Returning processed summary result (subset) to UI:",
      finalResult
    );

    // Display a toast indicating partial analysis was done
    toast.info(analysisNote);

    return finalResult;

    // General Catch Block
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (error: any) {
    console.error("Error in analyzeFile function:", error);
    // Avoid duplicate toasts if already handled by specific error throws above
    const knownErrorPrefixes = [
      "API request failed:",
      "File content is empty.",
      `First ${MAX_ROWS_TO_SEND} lines are empty.`,
      "Failed to read file as text.",
      "File reading error.",
      "Invalid API summary response format.",
      "Received an OK response, but failed to parse JSON body.",
    ];
    const isKnownError = knownErrorPrefixes.some((prefix) =>
      error.message?.startsWith(prefix)
    );

    if (!isKnownError) {
      toast.error(
        `An unexpected error occurred: ${error.message || "Unknown error"}`
      );
    }
    // Re-throw the error for potential higher-level handling or logging
    throw error;
  }
};

// Optional: Export endpoints if used elsewhere
export const API_ENDPOINTS = {
  ANALYZE: API_ENDPOINT,
};