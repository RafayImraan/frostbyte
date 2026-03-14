import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        midnight: "#0a1020",
        carbon: "#0f172a",
        neon: "#39ffb4",
        plasma: "#5ad7ff",
        ember: "#ff8a5c",
      },
      fontFamily: {
        display: ["var(--font-display)", "ui-sans-serif", "system-ui"],
        body: ["var(--font-body)", "ui-sans-serif", "system-ui"],
      },
      boxShadow: {
        glow: "0 0 25px rgba(57, 255, 180, 0.35)",
        haze: "0 20px 60px rgba(15, 23, 42, 0.45)",
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(90, 215, 255, 0.14) 1px, transparent 1px), linear-gradient(90deg, rgba(90, 215, 255, 0.14) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};

export default config;
