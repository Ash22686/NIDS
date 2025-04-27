
import React from "react";
import { useLocation } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

const NotFound = () => {
  const location = useLocation();

  return (
    <div className="min-h-[calc(100vh-150px)] flex flex-col items-center justify-center px-4 py-16">
      <div className="text-center max-w-md">
        <h1 className="text-6xl font-bold text-primary mb-4">404</h1>
        <p className="text-xl font-medium text-slate-700 mb-6">
          Page not found
        </p>
        <p className="text-slate-600 mb-8">
          The page <span className="font-mono bg-slate-100 px-2 py-1 rounded">{location.pathname}</span> you're looking for doesn't exist or has been moved.
        </p>
        
        <Button asChild className="w-full md:w-auto">
          <Link to="/">Return to Dashboard</Link>
        </Button>
      </div>
    </div>
  );
};

export default NotFound;
