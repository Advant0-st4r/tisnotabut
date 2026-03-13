export function validateCSVHeaders(rawHeaders) {
  const headers = rawHeaders.map(h => h.trim().toLowerCase());
  const isValid = headers.includes("capability") || headers.includes("name");
  
  if (!isValid) {
    const detectedHeaders = rawHeaders.join(", ");
    return {
      isValid: false,
      error: `Invalid CSV\n\nYour file must contain a column named:\nCapability\nor\nname\n\nDetected headers:\n${detectedHeaders}\n\nDownload the sample CSV to see the expected structure.`
    };
  }
  
  return { isValid: true };
}
