
import React from 'react';
import { Link } from 'react-router-dom';
import { Database } from 'lucide-react';

const Header = () => {
  return (
    <header className="bg-white shadow-sm border-b border-slate-200">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <Link to="/" className="flex items-center gap-2 text-secondary hover:text-primary transition-colors">
          <Database className="h-6 w-6 text-primary" />
          <span className="font-bold text-xl">NIDS</span>
        </Link>
        
        <nav>
          <ul className="flex items-center gap-6">
            <li>
              <Link 
                to="/" 
                className="text-slate-600 hover:text-primary font-medium transition-colors"
              >
                Dashboard
              </Link>
            </li>
            <li>
              <Link 
                to="/about" 
                className="text-slate-600 hover:text-primary font-medium transition-colors"
              >
                About
              </Link>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
};

export default Header;
