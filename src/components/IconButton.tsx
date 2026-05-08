import type { ReactNode } from "react";

/// Small square button that wraps an icon. Used for delete-style actions
/// where a text label would crowd the row — the icon makes the action
/// obvious. The `danger` variant tints the icon red so an accidental
/// click is still visually loud.
export function IconButton({
  children,
  onClick,
  ariaLabel,
  title,
  danger,
  disabled,
}: {
  children: ReactNode;
  onClick: () => void;
  ariaLabel: string;
  title: string;
  danger?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      title={title}
      onClick={onClick}
      disabled={disabled}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: "1.85rem",
        height: "1.85rem",
        padding: 0,
        background: "transparent",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm, 6px)",
        color: danger ? "var(--red)" : "var(--fg-2)",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {children}
    </button>
  );
}
