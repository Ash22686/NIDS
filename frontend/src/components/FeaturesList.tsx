
import React from 'react';
import { Card, CardContent } from '@/components/ui/card';

const FeaturesList = () => {
  // Example list of common network intrusion detection features
  const featureGroups = [
    {
      title: "Basic Features",
      features: [
        "duration", "protocol_type", "service", "flag",
        "src_bytes", "dst_bytes", "land", "wrong_fragment",
        "urgent"
      ]
    },
    {
      title: "Content Features",
      features: [
        "hot", "num_failed_logins", "logged_in", "num_compromised",
        "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login"
      ]
    },
    {
      title: "Time-based Traffic Features",
      features: [
        "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate"
      ]
    },
    {
      title: "Host-based Traffic Features",
      features: [
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate"
      ]
    }
  ];

  return (
    <div className="mt-6">
      <h3 className="text-xl font-semibold mb-4">Required Features (41 Total)</h3>
      <p className="mb-4 text-slate-600">
        Your CSV file must contain the following 41 features for accurate intrusion detection analysis:
      </p>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {featureGroups.map((group, idx) => (
          <Card key={idx}>
            <CardContent className="pt-6">
              <h4 className="font-medium mb-2 text-primary">{group.title}</h4>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                {group.features.map((feature, featureIdx) => (
                  <div key={featureIdx} className="text-sm text-slate-700">
                    {feature}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      
      <p className="mt-6 text-sm text-slate-500">
        The model requires all 41 features in the correct format. Please ensure your CSV follows this structure.
      </p>
    </div>
  );
};

export default FeaturesList;
