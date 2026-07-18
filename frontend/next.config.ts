import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Keep Next inside this project instead of selecting an unrelated parent lockfile.
  outputFileTracingRoot: __dirname,
};
export default nextConfig;
