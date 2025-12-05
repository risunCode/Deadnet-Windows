/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/**/*.{html,js}",
  ],
  theme: {
    extend: {
      colors: {
        // Hacker theme (default)
        hacker: {
          bg: '#0a0a0a',
          card: '#111111',
          border: '#1a1a1a',
          primary: '#00ff00',
          secondary: '#00cc00',
          text: '#00ff00',
          muted: '#006600'
        },
        // Maroon theme
        maroon: {
          bg: '#1a0a0a',
          card: '#2a1515',
          border: '#3a2020',
          primary: '#dc2626',
          secondary: '#b91c1c',
          text: '#fca5a5',
          muted: '#7f1d1d'
        },
        // Defender theme (blue)
        defender: {
          bg: '#0a0a1a',
          card: '#111122',
          border: '#1a1a3a',
          primary: '#3b82f6',
          secondary: '#2563eb',
          text: '#93c5fd',
          muted: '#1e40af'
        },
        // Pure dark theme
        dark: {
          bg: '#000000',
          card: '#0d0d0d',
          border: '#1a1a1a',
          primary: '#ffffff',
          secondary: '#a3a3a3',
          text: '#e5e5e5',
          muted: '#525252'
        }
      }
    },
  },
  plugins: [],
}
