// Terminal colors, shared by the CLI and the text reports.

export type Paint = (s: unknown) => string;

/** ANSI painters that return the text unchanged when color is off. */
export function palette(enabled: boolean | undefined): { red: Paint; green: Paint; yellow: Paint; dim: Paint; bold: Paint; cyan: Paint; bySeverity: Record<string, Paint> } {
  const c = (code: number): Paint => (s) => (enabled ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const red = c(31), green = c(32), yellow = c(33), dim = c(2), bold = c(1), cyan = c(36);
  return { red, green, yellow, dim, bold, cyan, bySeverity: { high: red, medium: yellow, low: dim, none: green } };
}
