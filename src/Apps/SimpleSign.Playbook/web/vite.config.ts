import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// `npm run dev` serves the UI on :5175 with hot reload and proxies the API to the Playbook app (dotnet run, :5400).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "./src") } },
  server: { port: 5175, proxy: { "/api": "http://127.0.0.1:5400" } },
  build: { outDir: "dist", emptyOutDir: true },
})
