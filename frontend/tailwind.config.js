/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './styles/**/*.css',
  ],
  theme: {
    extend: {
      colors: {
        // The product is dark-mode only; slate is the canonical surface ramp.
        surface: {
          DEFAULT: '#0f172a',
          900: '#0f172a',
          850: '#131c31',
          800: '#1e293b',
        },
        // Threat bands: cyan (clean) -> amber (suspicious) -> red (malicious).
        threat: {
          safe: '#22d3ee',
          low: '#38bdf8',
          medium: '#f59e0b',
          high: '#fb7185',
          critical: '#f43f5e',
          unknown: '#94a3b8',
        },
      },
      fontFamily: {
        sans: [
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Liberation Mono',
          'Courier New',
          'monospace',
        ],
      },
      boxShadow: {
        'neon-cyan': '0 0 45px -12px rgba(34, 211, 238, 0.65)',
        'neon-amber': '0 0 45px -12px rgba(245, 158, 11, 0.65)',
        'neon-red': '0 0 45px -12px rgba(244, 63, 94, 0.7)',
        glass: '0 8px 32px -8px rgba(2, 6, 23, 0.75)',
      },
      backgroundImage: {
        'grid-slate':
          'linear-gradient(to right, rgba(148, 163, 184, 0.07) 1px, transparent 1px), linear-gradient(to bottom, rgba(148, 163, 184, 0.07) 1px, transparent 1px)',
        'radial-fade':
          'radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34, 211, 238, 0.13), transparent 70%)',
      },
      backgroundSize: {
        grid: '44px 44px',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: '0.55', transform: 'scale(1)' },
          '50%': { opacity: '1', transform: 'scale(1.02)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'spin-slow': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
      animation: {
        'pulse-glow': 'pulse-glow 2.6s ease-in-out infinite',
        scanline: 'scanline 2.4s linear infinite',
        shimmer: 'shimmer 1.8s infinite',
        'fade-up': 'fade-up 0.45s ease-out both',
        'spin-slow': 'spin-slow 8s linear infinite',
      },
      transitionDuration: {
        1200: '1200ms',
      },
    },
  },
  plugins: [],
};
