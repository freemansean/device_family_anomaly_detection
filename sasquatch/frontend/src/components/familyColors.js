// Deterministic color assignment per device family.
// Fixed colors for well-known families; hash-derived hues for dynamic ones.
const FIXED = {
  "iPhone":         "#7ec8e3",
  "iPad":           "#5b9fd4",
  "MacBook":        "#3a78b5",
  "Apple":          "#2a5d96",
  "Android Phone":  "#7dcfaa",
  "Android Tablet": "#4aab7a",
  "Windows":        "#88aaee",
  "Chromebook":     "#aad466",
  "Linux":          "#d4b84a",
  "Printer":        "#e09a55",
  "Unknown":        "#555555",
};

export function familyColor(family) {
  if (FIXED[family]) return FIXED[family];
  // Deterministic hue from name hash
  let hash = 0;
  for (let i = 0; i < family.length; i++) {
    hash = (family.charCodeAt(i) + ((hash << 5) - hash)) | 0;
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 60%, 58%)`;
}
