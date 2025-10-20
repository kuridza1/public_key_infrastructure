export function extractBlobError(err: any): Promise<string> {
  return new Promise((resolve) => {
    if (err.error instanceof Blob) {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => resolve('Failed to read error blob');
      reader.readAsText(err.error);
    } else {
      resolve(typeof err === 'string' ? err : JSON.stringify(err));
    }
  });
}
