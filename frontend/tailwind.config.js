/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Backlinko Clean Growth Design System Palette
        primary: {
          DEFAULT: '#00BC98',
          hover: '#00a887',
          dim: 'rgba(0, 188, 152, 0.08)',
          glow: 'rgba(0, 188, 152, 0.25)',
        },
        secondary: {
          DEFAULT: '#000000',
        },
        tertiary: {
          DEFAULT: '#FF6A2A',
          hover: '#e8591c',
          dim: 'rgba(255, 106, 42, 0.08)',
        },
        neutral: '#FFFFFF',
        surface: '#FFFFFF',
        'on-surface': '#000000',
        muted: {
          DEFAULT: '#424348',
          light: '#65676e',
        },
        border: {
          DEFAULT: '#CED4DA',
          subtle: '#EEF2F7',
          dark: '#ADB5BD',
        },
        subtle: {
          DEFAULT: '#EEF2F7',
          hover: '#e2e8f0',
        },
        success: '#00BC98',
        error: {
          DEFAULT: '#D92D20',
          hover: '#b91c1c',
          dim: 'rgba(217, 45, 32, 0.08)',
        },
        slate: {
          850: '#131e36',
          925: '#0b1324',
          950: '#080c14',
        },
        cyan: {
          450: '#00d0e6',
          550: '#00c2d6',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      borderRadius: {
        none: '0px',
        sm: '4px',
        md: '6px',
        lg: '8px',
        xl: '12px',
        full: '9999px',
      },
      spacing: {
        xs: '8px',
        sm: '16px',
        md: '30px',
        lg: '40px',
        xl: '66px',
      },
      boxShadow: {
        flat: 'none',
        card: '0 1px 3px rgba(0, 0, 0, 0.04)',
      },
    },
  },
  plugins: [],
}


