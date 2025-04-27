
import React, { useState } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Upload } from 'lucide-react';
import { cn } from '@/lib/utils';
import { analyzeFile } from '@/services/api';

interface FileUploaderProps {
  onResultsReceived: (results: any) => void;
  setIsLoading: (loading: boolean) => void;
}

const FileUploader = ({ onResultsReceived, setIsLoading }: FileUploaderProps) => {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      
      if (selectedFile.type !== 'text/csv' && !selectedFile.name.endsWith('.csv')) {
        toast.error('Please upload a CSV file');
        return;
      }
      
      if (selectedFile.size > 10 * 1024 * 1024) { // 10MB limit
        toast.error('File size exceeds 10MB limit');
        return;
      }
      
      setFile(selectedFile);
      toast.success(`File "${selectedFile.name}" selected`);
    }
  };
  
  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };
  
  const handleDragLeave = () => {
    setIsDragging(false);
  };
  
  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      
      if (droppedFile.type !== 'text/csv' && !droppedFile.name.endsWith('.csv')) {
        toast.error('Please upload a CSV file');
        return;
      }
      
      if (droppedFile.size > 10 * 1024 * 1024) { // 10MB limit
        toast.error('File size exceeds 10MB limit');
        return;
      }
      
      setFile(droppedFile);
      toast.success(`File "${droppedFile.name}" selected`);
    }
  };
  
  const handleSubmit = async () => {
    if (!file) {
      toast.error('Please select a file first');
      return;
    }
    
    setIsLoading(true);
    
    try {
      const results = await analyzeFile(file);
      onResultsReceived(results);
      toast.success('Analysis complete!');
    } catch (error) {
      toast.error('Error analyzing file');
      console.error('Error:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="w-full max-w-2xl mx-auto">
      <div 
        className={cn(
          "border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors",
          isDragging ? "border-primary bg-blue-50" : "border-slate-300 hover:border-primary",
        )}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <Upload className="w-12 h-12 mx-auto mb-4 text-slate-400" />
        
        <h3 className="text-lg font-medium mb-2">
          {file ? file.name : 'Drop your CSV file here or click to browse'}
        </h3>
        
        <p className="text-sm text-slate-500 mb-4">
          Upload a CSV file containing the 41 required network features
        </p>
        
        <input
          type="file"
          id="file-upload"
          accept=".csv"
          onChange={handleFileChange}
          className="hidden"
        />
        
        <label htmlFor="file-upload">
          <Button variant="outline" className="mr-2" type="button" onClick={() => document.getElementById('file-upload')?.click()}>
            Choose File
          </Button>
        </label>
        
        {file && (
          <Button onClick={handleSubmit} className="ml-2">
            Analyze File
          </Button>
        )}
      </div>
      
      {file && (
        <div className="mt-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
          <h4 className="font-medium">Selected File:</h4>
          <p className="text-sm text-slate-600">{file.name} ({(file.size / 1024).toFixed(2)} KB)</p>
        </div>
      )}
    </div>
  );
};

export default FileUploader;
