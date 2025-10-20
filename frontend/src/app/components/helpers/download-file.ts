export function downloadFile(blob: Blob, fileName: string) {
  const file = new Blob([blob], { type: 'application/x-pkcs12' });
  const fileURL = window.URL.createObjectURL(file);

  const a = document.createElement('a');
  a.href = fileURL;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  window.URL.revokeObjectURL(fileURL);
}
