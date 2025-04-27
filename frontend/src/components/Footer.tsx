
import React from 'react';

const Footer = () => {
  return (
    <footer className="bg-secondary text-white py-8 mt-auto">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="mb-4 md:mb-0">
            <p className="text-sm">
              &copy; {new Date().getFullYear()} Network Intrusion Detection System
            </p>
          </div>
          <div className="flex flex-col md:flex-row items-center gap-4">
            <p className="text-sm text-slate-300">
              Built with security in mind
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
