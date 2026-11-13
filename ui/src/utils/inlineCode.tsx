import React from "react";

/**
 * Renders paired inline backtick spans (e.g. "run `sudo setcap ...`")
 * as styled `<code className="mono">` elements without using dangerouslySetInnerHTML.
 */
export function renderInlineCode(text: string | null | undefined): React.ReactNode {
  if (!text) return text ?? null;
  if (!text.includes("`")) return text;
  const parts = text.split(/`([^`]+)`/g);
  return parts.map((part, idx) =>
    idx % 2 === 1 ? (
      <code key={idx} className="mono">
        {part}
      </code>
    ) : (
      <React.Fragment key={idx}>{part}</React.Fragment>
    ),
  );
}
