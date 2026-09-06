/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Dark-first security dashboard palette (DESIGN.md §3-4)
        base: {
          950: '#0a0e14',
          900: '#0f141b',
          850: '#131a23',
          800: '#1a2230',
          700: '#243040',
          600: '#314155',
        },
        borderline: '#232d3d',
        critical: '#f43f5e',
        high: '#f97316',
        medium: '#eab308',
        low: '#38bdf8',
        informational: '#94a3b8',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', '"Courier New"', 'monospace'],
      },
    },
  },
  plugins: [],
};