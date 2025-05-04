// src/components/FileUploader.tsx
import React, { useState, useCallback } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button'; // Assuming Shadcn UI Button
import { Upload, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils'; // Assuming standard Shadcn utility
import { analyzeFile, AnalysisSummaryResult } from '@/services/api'; // Adjust path as needed

interface FileUploaderProps {
  onResultsReceived: (results: AnalysisSummaryResult | null) => void; // Expect summary or null
  isLoading: boolean; // Receive loading state from parent
  setIsLoading: (loading: boolean) => void; // Receive setter from parent
}

const FileUploader = ({ onResultsReceived, isLoading, setIsLoading }: FileUploaderProps) => {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const validateFile = (selectedFile: File): boolean => {
    // Check type and extension
    if (selectedFile.type !== 'text/csv' && !selectedFile.name.toLowerCase().endsWith('.csv')) {
      toast.error('Invalid file type. Please upload a CSV file.');
      return false;
    }
    // Check size (e.g., 10MB limit)
    const maxSize = 10 * 1024 * 1024;
    if (selectedFile.size > maxSize) {
      toast.error(`File size exceeds ${maxSize / (1024 * 1024)}MB limit.`);
      return false;
    }
    // Basic check for empty file
    if (selectedFile.size === 0) {
      toast.error('File appears to be empty.');
      return false;
    }
    return true;
  };

  const handleFileSelect = useCallback((selectedFile: File | null) => {
    if (selectedFile && validateFile(selectedFile)) {
      setFile(selectedFile);
      toast.success(`File "${selectedFile.name}" selected. Ready for analysis.`);
      onResultsReceived(null); // Clear previous results when a new file is selected
    } else {
      setFile(null); // Clear selection if invalid
    }
  }, [onResultsReceived]); // Dependency ensures onResultsReceived is stable if memoized


  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    handleFileSelect(e.target.files?.[0] ?? null);
    // Reset input value to allow re-uploading the same file name
    e.target.value = '';
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault(); // Necessary to allow drop
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelect(e.dataTransfer.files[0]);
      e.dataTransfer.clearData(); // Clean up
    }
  };

  const handleSubmit = async () => {
    if (!file) {
      toast.error('Please select a valid CSV file first.');
      return;
    }

    setIsLoading(true);
    onResultsReceived(null); // Clear previous results before analysis starts

    try {
      const results = await analyzeFile(file); // Call the updated API function
      onResultsReceived(results); // Pass the summary results up
      toast.success('Analysis complete! Summary generated.');
    } catch (error) {
      console.error('Error during file analysis submission:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // No longer need triggerFileInput function

  return (
    <div className="w-full max-w-2xl mx-auto">
      {/* Outer div is now primarily for drag/drop and styling */}
      <div
        className={cn(
          "relative border-2 border-dashed rounded-lg p-8 text-center transition-colors duration-200 ease-in-out",
          // Remove focus styles from the div if it's not meant to be interactive via keyboard directly
          // "focus-within:ring-2 focus-within:ring-primary focus-within:ring-offset-2",
          isDragging
            ? "border-primary bg-primary/10"
            : "border-slate-300 dark:border-slate-700", // Removed hover styles that imply clickability
          // Background change on drag is sufficient visual feedback
          isLoading ? "bg-slate-50 dark:bg-slate-800/50" : "" // Background hint for loading
        )}
        onDragOver={handleDragOver}
        onDragEnter={handleDragOver} // Handle enter as well
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      // REMOVED onClick={triggerFileInput} from the main div
      >
        {/* Hidden actual file input */}
        <input
          type="file"
          id="file-upload" // ID is crucial for the label
          accept=".csv,text/csv"
          onChange={handleFileChange}
          className="hidden" // Visually hide it, but it's still functional
          disabled={isLoading}
          aria-label="Upload CSV file" // Keep aria-label for accessibility if label text isn't sufficient
        />

        {/* Content area */}
        <div className="flex flex-col items-center justify-center">
          <Upload
            className={cn(
              "w-12 h-12 mx-auto mb-4",
              isDragging ? "text-primary" : "text-slate-400 dark:text-slate-500"
            )}
            aria-hidden="true"
          />

          <h3 className="text-lg font-medium mb-2 text-slate-900 dark:text-slate-100">
            {file ? file.name : 'Drop CSV file here or click "Choose File"'}
          </h3>

          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
            Requires headerless CSV, max 10MB, 43 columns expected.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-2">
            {/* Use a Button styled as outline, wrapping a label */}
            {/* 'asChild' makes the Button render the <label> instead of a <button> */}
            <Button variant="outline" asChild disabled={isLoading}>
              <label
                htmlFor="file-upload" // Connects label to the input
                className={cn(
                  "cursor-pointer", // Make label look clickable
                  isLoading ? "cursor-not-allowed opacity-50" : ""
                )}
              >
                Choose File
              </label>
            </Button>

            {/* Analyze Button */}
            {file && (
              <Button
                onClick={handleSubmit} // No need for stopPropagation anymore
                disabled={isLoading || !file}
                aria-label={`Analyze file ${file.name}`}
              >
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                ) : null}
                {isLoading ? 'Analyzing...' : 'Analyze File'}
              </Button>
            )}
          </div> {/* End button group flex container */}

        </div> {/* End content area */}
      </div> {/* End outer dropzone div */}

      {/* Display file details */}
      {file && !isLoading && (
        <div className="mt-4 p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 text-sm">
          <h4 className="font-medium mb-1 text-slate-800 dark:text-slate-200">Selected File:</h4>
          <p className="text-slate-600 dark:text-slate-400 truncate">{file.name}</p>
          <p className="text-slate-600 dark:text-slate-400">Size: {(file.size / 1024).toFixed(2)} KB</p>
        </div>
      )}
    </div>
  );
};

export default FileUploader;