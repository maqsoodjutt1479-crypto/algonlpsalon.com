/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        display: ['"Playfair Display"', "serif"],
        body: ['"Manrope"', "system-ui", "sans-serif"],
        arabic: ['"Noto Naskh Arabic"', '"Manrope"', "serif"]
      },
      colors: {
        sand: {
          50: "#fbf7f2",
          100: "#f4ede3",
          200: "#e6d5c3",
          300: "#d3b79d",
          400: "#c19c78",
          500: "#aa7f57",
          600: "#8a6344",
          700: "#6a4a35",
          800: "#493327",
          900: "#2c1f18"
        },
        noir: {
          50: "#f6f4f2",
          100: "#e7e1dc",
          200: "#c9beb4",
          300: "#a79a8d",
          400: "#7f7267",
          500: "#5b5048",
          600: "#3e362f",
          700: "#2c2621",
          800: "#1c1714",
          900: "#120f0d"
        }
      }
    }
  },
  plugins: []
};
