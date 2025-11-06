// Minimal ambient module shims for optional parsing libs used server-side.
// These quiet TS without pulling in heavy type packages.
declare module "tesseract.js";
declare module "pdfjs-dist";
declare module "pdfjs-dist/build/pdf";
declare module "canvas";

// General fallbacks for any CommonJS imports that lack types.
declare module "*?cjs";

// pdf.js legacy build shims
declare module "pdfjs-dist/legacy/build/pdfjs";
declare module "pdfjs-dist/legacy/build/pdf";
