
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { motion } from 'framer-motion';

const About = () => {
  const attackTypes = [
    {
      name: "DoS (Denial of Service)",
      description: "Attacks designed to make network resources unavailable to users by flooding the system with excessive requests.",
      examples: "SYN flood, UDP flood, ICMP flood, HTTP flood"
    },
    {
      name: "Probe (Scanning/Reconnaissance)",
      description: "Attempts to gather information about network systems and services for potential exploitation.",
      examples: "Port scanning, vulnerability scanning, network mapping"
    },
    {
      name: "R2L (Remote to Local)",
      description: "Unauthorized access attempts from a remote machine to gain local access to a system.",
      examples: "Password guessing, buffer overflow attacks, social engineering"
    },
    {
      name: "U2R (User to Root)",
      description: "Attempts by a normal user to gain administrator/root privileges without authorization.",
      examples: "Privilege escalation, buffer overflow exploits, software vulnerabilities"
    },
    {
      name: "Normal",
      description: "Regular network traffic with no malicious intent.",
      examples: "Standard user activity, system updates, routine communications"
    }
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.2
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.5
      }
    }
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="text-center mb-12"
      >
        <h1 className="text-4xl font-bold text-secondary mb-4 bg-gradient-to-r from-secondary to-primary bg-clip-text text-transparent">
          About Network Traffic Analysis
        </h1>
        <p className="text-xl text-slate-600 max-w-3xl mx-auto">
          Understanding how our Network Intrusion Detection System works to protect your infrastructure.
        </p>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="bg-white rounded-xl shadow-md p-8 mb-12 hover:shadow-xl transition-shadow duration-300"
      >
        <h2 className="text-2xl font-bold mb-6 text-secondary">Network Traffic Analysis</h2>
        
        <div className="prose max-w-none text-slate-700">
          <p className="leading-relaxed">
            Network Intrusion Detection Systems (NIDS) monitor network traffic for suspicious activity 
            and alert system administrators when potential threats are detected. Our system analyzes 
            pre-extracted features from network traffic to identify various types of attacks.
          </p>
          
          <h3 className="text-xl font-semibold mt-8 mb-4 text-secondary">Detection Approaches</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <motion.div
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <Card className="hover:border-primary/50 transition-colors duration-300">
                <CardContent className="pt-6">
                  <h4 className="font-medium mb-2 text-primary">Signature-Based Detection</h4>
                  <p className="text-sm">
                    This approach compares observed events against a database of known threat signatures. 
                    If a match is found, an alert is triggered. Effective against known threats but cannot 
                    detect novel or zero-day attacks.
                  </p>
                </CardContent>
              </Card>
            </motion.div>
            
            <motion.div
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <Card className="hover:border-primary/50 transition-colors duration-300">
                <CardContent className="pt-6">
                  <h4 className="font-medium mb-2 text-primary">Anomaly-Based Detection</h4>
                  <p className="text-sm">
                    This approach builds a model of normal behavior and flags deviations from this model. 
                    It can detect previously unknown attacks but may generate false positives if normal 
                    behavior changes.
                  </p>
                </CardContent>
              </Card>
            </motion.div>
          </div>
          
          <p className="leading-relaxed">
            Our system utilizes machine learning models trained on extensive datasets containing both normal 
            and malicious network traffic patterns. This enables accurate classification of network activities 
            into different categories of threats.
          </p>
          
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.4 }}
          >
            <h3 className="text-xl font-semibold mt-8 mb-4 text-secondary">Feature Extraction</h3>
            
            <p className="leading-relaxed">
              The effectiveness of a NIDS depends heavily on the quality of features extracted from network traffic. 
              Our system analyzes 41 specific features derived from network connections, including:
            </p>
            
            <ul className="list-disc pl-6 mb-6 grid grid-cols-1 md:grid-cols-2 gap-x-6 mt-4">
              <motion.li className="text-slate-600" variants={itemVariants}>Duration and protocol type</motion.li>
              <motion.li className="text-slate-600" variants={itemVariants}>Source and destination bytes</motion.li>
              <motion.li className="text-slate-600" variants={itemVariants}>Connection status flags</motion.li>
              <motion.li className="text-slate-600" variants={itemVariants}>Error rates and fragment information</motion.li>
              <motion.li className="text-slate-600" variants={itemVariants}>Login attempt statistics</motion.li>
              <motion.li className="text-slate-600" variants={itemVariants}>Host-based traffic features</motion.li>
            </ul>
          </motion.div>
        </div>
      </motion.div>

      <motion.div
        initial="hidden"
        animate="visible"
        variants={containerVariants}
        className="bg-slate-50 rounded-xl p-8 border border-slate-200"
      >
        <h2 className="text-2xl font-bold mb-6 text-center text-secondary">Attack Classifications</h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {attackTypes.map((attack, index) => (
            <motion.div
              key={index}
              variants={itemVariants}
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <Card className={`${attack.name === "Normal" ? "border-green-200" : ""} hover:border-primary/50 transition-colors duration-300`}>
                <CardContent className="pt-6">
                  <h4 className="font-semibold mb-2 text-primary text-lg">{attack.name}</h4>
                  <p className="text-slate-700 mb-4">{attack.description}</p>
                  <p className="text-sm text-slate-500"><span className="font-medium">Examples:</span> {attack.examples}</p>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
};

export default About;
