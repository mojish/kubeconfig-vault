import { build } from "esbuild";
await build({ entryPoints: ["web/app.mjs"], outfile: "web/app.js", bundle: true,
  format: "esm", target: "es2023", platform: "browser", legalComments: "inline" });
