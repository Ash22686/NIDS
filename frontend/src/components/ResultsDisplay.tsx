// src/components/ResultsDisplay.tsx
import React, { useMemo } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell
} from 'recharts';
import { jsPDF } from 'jspdf';
import { toast } from 'sonner';
import autoTable from 'jspdf-autotable'; // Ensure types are installed: npm install @types/jspdf-autotable --save-dev
import { Download, FileText, AlertCircle, Info } from 'lucide-react';
import { AnalysisSummaryResult } from '@/services/api'; // Adjust path as needed
import { Button } from "@/components/ui/button"; // Assuming Shadcn UI
import {
  Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle,
} from "@/components/ui/card";
import { cn } from '@/lib/utils'; // Assuming standard Shadcn utility
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"; // Assuming Shadcn UI Alert

// --- Props Definition ---
interface ResultsDisplayProps {
  results: AnalysisSummaryResult | null; // Expect the summary object or null
}

// --- Color mapping for chart/table (Consistent with backend's attack_mapping keys) ---
const PREDICTION_COLORS: { [key: string]: string } = {
  'Normal': '#10B981', // Emerald 500 / Green
  'DoS': '#EF4444',    // Red 500
  'Probe': '#F59E0B',  // Amber 500 / Orange
  'R2L': '#EAB308',    // Yellow 500
  'U2R': '#A855F7',    // Purple 500
  'Unknown': '#6B7280' // Gray 500
};
// Default color for categories not explicitly mapped
const DEFAULT_COLOR = '#8884d8'; // Recharts default purple

const ResultsDisplay = ({ results }: ResultsDisplayProps) => {

  // Memoize chart data transformation to avoid re-calculation on every render
  const chartData = useMemo(() => {
    if (!results?.summary) return [];
    return Object.entries(results.summary)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count); // Sort descending by count
  }, [results?.summary]);


  if (!results) {
    return null; // Don't render anything if there are no results
  }

  // --- PDF Download Handler ---
  const handleDownloadPdf = () => {
    if (!results) return;

    const doc = new jsPDF();
    const tableStartY = 25; // Starting Y position for the table

    // --- Document Header ---
    doc.setFontSize(18);
    doc.setTextColor(40); // Dark Gray
    doc.text("Network Traffic Analysis Summary", 14, 15);

    // --- File Information ---
    doc.setFontSize(10);
    doc.setTextColor(100); // Lighter Gray
    doc.text(`File Name: ${results.fileName}`, 14, tableStartY - 5);
    doc.text(`Analysis Timestamp: ${new Date(results.timestamp).toLocaleString()}`, 14, tableStartY);
    // Add file size info
    const fileSizeKB = (results.fileSize / 1024).toFixed(2);
    const fileSizeMB = (results.fileSize / (1024 * 1024)).toFixed(2);
    doc.text(`File Size: ${fileSizeKB} KB (${fileSizeMB} MB)`, 105, tableStartY); // Position to the right

    // --- Summary Table ---
    const head = [['Classification Type', 'Number of Records']];
    const body = chartData.map(item => [item.name, item.count.toLocaleString()]); // Format count

    autoTable(doc, {
      startY: tableStartY + 8,
      head: head,
      body: body,
      theme: 'grid',
      headStyles: {
        fillColor: [22, 160, 133], // Teal-like color for header
        textColor: [255, 255, 255], // White text
        fontStyle: 'bold',
      },
      didParseCell: (data) => {
        // --- Row Styling based on Classification ---
        // Apply styling only to body cells in the first column (Classification Type)
        if (data.section === 'body' && data.column.index === 0) {
          const category = data.cell.raw as string;
          const color = PREDICTION_COLORS[category] || DEFAULT_COLOR;
          data.cell.styles.textColor = color; // Set text color
          data.cell.styles.fontStyle = 'bold';
        }
        // Optional: Apply a light background fill based on category
        // if (data.section === 'body') {
        //     const category = data.row.raw[0] as string; // Get category from first column of the row
        //     const hexColor = PREDICTION_COLORS[category];
        //     if (hexColor) {
        //         // Very light fill (example: convert hex to RGB and use low alpha)
        //         // This requires a hex-to-rgb conversion function or library
        //         // data.cell.styles.fillColor = hexToRgbWithAlpha(hexColor, 0.05);
        //     }
        // }
      },
      margin: { left: 14, right: 14 } // Ensure table fits page width
    });

    // --- Summary Statistics Below Table ---
    const finalY = (doc as any).lastAutoTable.finalY || tableStartY + 50; // Get Y pos after table
    doc.setFontSize(10);
    doc.setTextColor(40); // Dark Gray
    const statsStartY = finalY + 10;
    doc.text(`Total Records in File: ${results.totalRows.toLocaleString()}`, 14, statsStartY);
    doc.text(`Records Successfully Processed: ${results.processedRows.toLocaleString()}`, 14, statsStartY + 5);
    doc.text(`Records with Errors (Skipped): ${results.errorRows.toLocaleString()}`, 14, statsStartY + 10);

    // --- Add Error Preview if available ---
    if (results.errorPreview && results.errorPreview.length > 0) {
      doc.setFontSize(10);
      doc.setTextColor(255, 0, 0); // Red for errors
      doc.text("Preview of Processing Errors:", 14, statsStartY + 18);
      doc.setTextColor(100); // Gray for details
      let errorY = statsStartY + 23;
      results.errorPreview.forEach((errMsg, index) => {
        if (errorY < 280) { // Prevent going off page
          doc.text(`- ${errMsg}`, 16, errorY);
          errorY += 4;
        } else if (index === results.errorPreview!.length - 1 && errorY >= 280) {
          doc.text('... (more errors exist)', 16, errorY);
        }
      });
    }


    // --- Footer ---
    const pageCount = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150);
      doc.text(`Page ${i} of ${pageCount}`, doc.internal.pageSize.width - 25, doc.internal.pageSize.height - 10);
      doc.text(`Generated: ${new Date().toLocaleString()}`, 14, doc.internal.pageSize.height - 10);
    }

    // --- Save the PDF ---
    // Clean filename (remove non-alphanumeric characters)
    const safeFileName = results.fileName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    doc.save(`analysis_summary_${safeFileName}.pdf`);
    toast.success("PDF summary downloaded.");
  };

  // --- Render component ---
  return (
    <div className="w-full max-w-4xl mx-auto mt-6 animate-fadeIn"> {/* Added fade-in animation class */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fadeIn { animation: fadeIn 0.5s ease-out forwards; }
      `}</style>
      <Card className="shadow-md dark:border-slate-700">
        <CardHeader>
          <CardTitle className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-2xl">
            <div className="flex items-center gap-2">
              <FileText className="h-6 w-6 text-primary flex-shrink-0" />
              Analysis Summary
            </div>
            {/* Move download button here for better placement on small screens */}
            <Button onClick={handleDownloadPdf} variant="outline" size="sm" className="mt-2 sm:mt-0 w-full sm:w-auto">
              <Download className="mr-2 h-4 w-4" />
              Download PDF
            </Button>
          </CardTitle>
          <CardDescription>
            Results for file: <span className="font-medium text-slate-700 dark:text-slate-300">{results.fileName}</span><br />
            Analyzed on {new Date(results.timestamp).toLocaleString()}
          </CardDescription>
          {/* Display error preview if present */}
          {results.errorRows > 0 && (
            <Alert variant="destructive" className="mt-4">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Processing Errors</AlertTitle>
              <AlertDescription>
                {results.errorRows.toLocaleString()} record(s) could not be processed.
                {results.errorPreview && results.errorPreview.length > 0 && (
                  <ul className="mt-2 list-disc list-inside text-xs">
                    {results.errorPreview.map((err, idx) => (
                      <li key={idx}>{err}</li>
                    ))}
                    {results.errorRows > results.errorPreview.length && <li>... and more</li>}
                  </ul>
                )}
                Check the CSV format and data types in the skipped rows.
              </AlertDescription>
            </Alert>
          )}
          {/* Info message if no attacks found */}
          {results.processedRows > 0 && chartData.length === 1 && chartData[0].name === 'Normal' && (
            <Alert variant="default" className="mt-4 bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800">
              <Info className="h-4 w-4 text-green-700 dark:text-green-300" />
              <AlertTitle className="text-green-800 dark:text-green-200">All Clear</AlertTitle>
              <AlertDescription className="text-green-700 dark:text-green-300">
                All {results.processedRows.toLocaleString()} processed records were classified as Normal.
              </AlertDescription>
            </Alert>
          )}
        </CardHeader>

        <CardContent className="space-y-8 pt-4"> {/* Add padding top */}
          {/* --- Bar Chart --- */}
          {chartData.length > 0 ? (
            <div>
              <h3 className="text-lg font-semibold mb-4 text-center text-slate-800 dark:text-slate-200">
                Prediction Distribution ({results.processedRows.toLocaleString()} Records)
              </h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={chartData}
                  margin={{ top: 5, right: 30, left: 0, bottom: 5 }}
                  barCategoryGap="20%" // Add gap between bars
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" className="dark:stroke-slate-700" />
                  <XAxis
                    dataKey="name"
                    tick={{ fontSize: 11, fill: '#64748b' }} // Tailwind slate-500
                    className="dark:fill-slate-400"
                    interval={0} // Show all labels if possible
                    angle={-15} // Slightly angle labels if many categories
                    textAnchor="end" // Anchor angled text correctly
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 11, fill: '#64748b' }}
                    className="dark:fill-slate-400"
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(200, 200, 200, 0.3)' }} // Light background on hover
                    contentStyle={{
                      backgroundColor: 'rgba(255, 255, 255, 0.9)',
                      border: '1px solid #ccc',
                      borderRadius: '5px',
                      fontSize: '12px'
                    }}
                    labelStyle={{ fontWeight: 'bold', color: '#333' }}
                    formatter={(value: number) => value.toLocaleString()} // Format tooltip value
                  />
                  <Legend
                    wrapperStyle={{ fontSize: '12px', paddingTop: '15px' }} // Style legend
                  />
                  <Bar dataKey="count" name="Record Count" radius={[4, 4, 0, 0]} > {/* Rounded top corners */}
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PREDICTION_COLORS[entry.name] || DEFAULT_COLOR} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-center text-slate-500 dark:text-slate-400">
              No data processed or no results to display.
            </p>
          )}

        </CardContent>

        <CardFooter className="flex flex-col sm:flex-row justify-between items-start sm:items-center pt-4 border-t dark:border-slate-700 mt-4">
          {/* Summary Stats */}
          <div className="text-xs text-slate-600 dark:text-slate-400 space-y-1">
            <p>Total Records: <span className='font-medium text-slate-800 dark:text-slate-200'>{results.totalRows.toLocaleString()}</span></p>
            <p>Processed: <span className='font-medium text-green-700 dark:text-green-400'>{results.processedRows.toLocaleString()}</span></p>
            <p>Errors (Skipped): <span className={cn('font-medium', results.errorRows > 0 ? 'text-red-700 dark:text-red-400' : 'text-slate-800 dark:text-slate-200')}>{results.errorRows.toLocaleString()}</span></p>
          </div>
          {/* Download button moved to header */}
        </CardFooter>
      </Card>
    </div>
  );
};

export default ResultsDisplay;