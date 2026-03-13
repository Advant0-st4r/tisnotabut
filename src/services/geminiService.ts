export const generateMetrics = async (capabilityName: string, domain: string, capabilityId: string) => {
  const response = await fetch("/api/metrics/generate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ capabilityId })
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to generate metrics");
  }
  
  return response.json();
};

export const generateVisualization = async (prompt: string) => {
  const response = await fetch("/api/visualizations", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ prompt })
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to generate visualization");
  }
  
  const data = await response.json();
  return data.imageData;
};