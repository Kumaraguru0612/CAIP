/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080C14",
          card: "rgba(13, 20, 35, 0.75)",
          border: "rgba(255, 255, 255, 0.08)",
          accent: "#00E5FF",
          primary: "#8B5CF6",
          success: "#10B981",
          warning: "#F59E0B",
          danger: "#EF4444"
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
