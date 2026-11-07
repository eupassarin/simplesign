import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// `npm run dev` serves the UI on :5174 with hot reload and proxies the API and services to the Sandbox (dotnet run, :5300).
const sandbox = "http://localhost:5300"
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: { port: 5174, proxy: { "/api": sandbox, "/aia": sandbox, "/crl": sandbox, "/root.pem": sandbox, "/chain.pem": sandbox } },
  build: { outDir: "dist", emptyOutDir: true },
})
