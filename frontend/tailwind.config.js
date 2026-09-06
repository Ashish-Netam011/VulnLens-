/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // VulnLens "security cockpit" surfaces — cool graphite, layered.
        base: {
          950: '#0a0e13',
          925: '#0c1117',
          900: '#0e141c',
          875: '#111823',
          850: '#141d2a',
          800: '#182233',
          750: '#1f2b3e',
          700: '#26344a',
          600: '#33445e',
        },
        // Hairlines / borders.
        edge: {
          faint: '#141b26',
          DEFAULT: '#1d2737',
          strong: '#2a3a52',
        },
        // Restrained interactive accent (indigo) + flow/accent tints.
        accent: {
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
        },
        flow: '#22d3ee',
        // Compatibility alias for legacy surfaces (kept during the redesign).
        borderline: '#1d2737',
        critical: '#fb4d63',
        high: '#f97316',
        medium: '#eab308',
        low: '#38bdf8',
        informational: '#94a3b8',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', '"Courier New"', 'monospace'],
      },
      boxShadow: {
        lift: '0 1px 0 rgba(255,255,255,0.03) inset, 0 10px 30px -12px rgba(0,0,0,0.55)',
        glowCritical: '0 0 0 1px rgba(251,77,99,0.35), 0 0 24px -6px rgba(251,77,99,0.35)',
        glowHigh: '0 0 0 1px rgba(249,115,22,0.3), 0 0 20px -6px rgba(249,115,22,0.3)',
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      letterSpacing: {
        widest2: '0.18em',
      },
    },
  },
  plugins: [],
};
