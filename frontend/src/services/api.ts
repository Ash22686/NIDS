// src/services/analysisService.ts (or appropriate file path)

import { toast } from "sonner";

// Defined API endpoint URL
const API_ENDPOINT = "http://localhost:5000/api/analyze"; // Matches the Flask route

// Type for the expected backend response (success case)
interface AnalysisSuccessResponse {
  prediction: string;
  // Backend currently doesn't return confidence, add if needed later
}

// Type for the expected backend response (error case)
interface AnalysisErrorResponse {
  error: string;
}

// Type for the data structure returned to the UI component
export interface AnalysisResult {
  prediction: string;
  confidence: number; // Currently a placeholder
  details: {
    timestamp: string;
    fileSize: number;
    fileName: string;
  };
}

// --- Constants for expected column counts ---
// Based on notebook_assigned_columns (includes 'attack' and 'last_flag')
const EXPECTED_COLUMNS_IN_FILE = 43;
// Based on original_form_columns in Flask (excludes 'attack')
const EXPECTED_COLUMNS_FOR_API = 42;
// Index of the 'attack' column in the 43-column list (0-based)
// It's the second-to-last column as per the Python definition.
const ATTACK_COLUMN_INDEX = 41;

// --- Helper Function to read file content as text ---
const readFileAsText = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        // Ensure only the first line is processed if multiple lines exist,
        // as the backend expects a single entry.
        const firstLine = reader.result.split("\n")[0].trim();
        resolve(firstLine);
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
 * Reads the first line of a file, processes the CSV data to match backend expectations,
 * sends it to the analysis API, and returns the result.
 * @param file The file object to analyze.
 * @returns A promise that resolves with the AnalysisResult or rejects with an error.
 */
export const analyzeFile = async (file: File): Promise<AnalysisResult> => {
  console.log(
    "Attempting to analyze file via API:",
    file.name,
    file.type,
    file.size
  );

  try {
    // 1. Read the file content (first line)
    let rawCsvString = await readFileAsText(file);
    console.log(
      "Raw file content (first line):",
      rawCsvString.substring(0, 100) + "..."
    );

    if (!rawCsvString) {
      toast.error("File appears to be empty or could not be read.");
      throw new Error("File content is empty.");
    }

    // 2. Remove potential leading/trailing quotes from the raw string
    // This is crucial if the file format includes them (e.g., "\"val1,val2,...\"")
    if (rawCsvString.startsWith('"') && rawCsvString.endsWith('"')) {
      rawCsvString = rawCsvString.substring(1, rawCsvString.length - 1);
      console.log("Stripped leading/trailing quotes from raw string.");
    } else {
      console.log(
        "No leading/trailing quotes found or string format mismatch."
      );
    }

    // 3. Parse and filter the potentially cleaned CSV string
    const values = rawCsvString.split(",");

    // 4. Validate the number of columns read from the file
    if (values.length !== EXPECTED_COLUMNS_IN_FILE) {
      const errorMsg = `File format error: Expected ${EXPECTED_COLUMNS_IN_FILE} columns in the first line, but found ${values.length}. Check the input file.`;
      console.error(errorMsg, "Raw values:", values);
      toast.error(errorMsg);
      throw new Error(errorMsg); // Specific error type
    } else {
      console.log(`Validated ${values.length} columns from file.`);
    }

    // 5. Remove the 'attack' column (at index 41) to get the 42 features for the API
    // Ensure the index is correct based on the Python 'notebook_assigned_columns' list.
    const valuesForApi = [
      ...values.slice(0, ATTACK_COLUMN_INDEX), // Elements before 'attack'
      ...values.slice(ATTACK_COLUMN_INDEX + 1), // Elements after 'attack'
    ];

    // 6. Double-check the length after removal
    if (valuesForApi.length !== EXPECTED_COLUMNS_FOR_API) {
      // This should ideally not happen if the logic above is correct
      const errorMsg = `Internal processing error: Expected ${EXPECTED_COLUMNS_FOR_API} columns after processing, got ${valuesForApi.length}.`;
      console.error(
        errorMsg,
        "Original values:",
        values,
        "API values:",
        valuesForApi
      );
      toast.error("Data processing error before sending to API.");
      throw new Error(errorMsg); // Specific error type
    } else {
      console.log(
        `Successfully processed data to ${valuesForApi.length} features for API.`
      );
    }

    // 7. Join the processed values back into a string
    const processedCsvString = valuesForApi.join(",");
    console.log(
      "Processed CSV string for API:",
      processedCsvString.substring(0, 100) + "..."
    );

    // 8. Send the *processed* content to the backend API endpoint
    console.log(`Sending POST request to ${API_ENDPOINT}`);
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json", // Essential header
      },
      // Send the processed string with 42 features, no surrounding quotes
      body: JSON.stringify({ csv_input: processedCsvString }),
    });
    console.log(`Received response with status: ${response.status}`);

    // 9. Handle the response
    if (!response.ok) {
      // Attempt to parse error message from backend if available
      let errorMessage = `Analysis failed (HTTP ${response.status}): ${response.statusText}`;
      try {
        const errorData: AnalysisErrorResponse = await response.json();
        if (errorData && errorData.error) {
          errorMessage = errorData.error; // Use specific error from backend
          console.error("Backend returned error:", errorMessage);
        } else {
          console.error(
            "Backend error response missing 'error' field:",
            errorData
          );
        }
      } catch (parseError) {
        // Ignore if response body isn't valid JSON or empty
        console.error(
          "Could not parse error response JSON, using status text.",
          parseError
        );
      }
      toast.error(`Analysis failed: ${errorMessage}`); // Display the error to the user
      throw new Error(`API request failed: ${errorMessage}`); // Propagate a typed error
    }

    // 10. Parse the successful JSON response
    const result: AnalysisSuccessResponse = await response.json();
    console.log("API Success Response:", result);

    if (!result || typeof result.prediction !== "string") {
      console.error("Invalid success response format from API:", result);
      toast.error("Received an invalid response from the server.");
      throw new Error("Invalid API response format.");
    }

    // 11. Return the data in the format expected by the UI component
    // (Add dummy confidence or modify UI to not expect it if backend doesn't provide it)
    const finalResult: AnalysisResult = {
      prediction: result.prediction,
      confidence: 0.95, // Placeholder: Replace or remove if backend provides confidence
      details: {
        timestamp: new Date().toISOString(),
        fileSize: file.size,
        fileName: file.name,
      },
    };
    console.log("Returning processed result to UI:", finalResult);
    return finalResult;

    // General Catch Block for unexpected errors during the process
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } catch (error: any) {
    console.error("Error in analyzeFile function:", error);
    // Avoid duplicate toasts if already handled by specific error throws above
    const knownErrorPrefixes = [
      "API request failed:",
      "File content is empty.",
      "File format error:",
      "Internal processing error:",
      "Failed to read file as text.",
      "File reading error.",
      "Invalid API response format.",
    ];
    // Check if the error message starts with any known prefix
    const isKnownError = knownErrorPrefixes.some((prefix) =>
      error.message?.startsWith(prefix)
    );

    if (!isKnownError) {
      toast.error("An unexpected error occurred during file analysis.");
    }
    // Re-throw the error for potential higher-level handling or logging
    throw error;
  }
};

// Optional: Export endpoints if used elsewhere, but not needed for analyzeFile itself
export const API_ENDPOINTS = {
  ANALYZE: API_ENDPOINT,
};