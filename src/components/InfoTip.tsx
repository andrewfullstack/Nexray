import { useEffect, useRef, useState, type ReactNode } from "react";

/// Hover/focus-activated tooltip used on the ⓘ icons next to features
/// like System proxy and TUN mode. Native `title=` attributes drop
/// formatting and word-wrap awkwardly; this gives us a styled popover
/// with multi-line content while staying keyboard-accessible.
///
/// The popover is portal-free (just absolute-positioned next to the
/// trigger) so it stays simple. It auto-flips left/right based on the
/// trigger's screen position to avoid clipping.
export function InfoTip({
  children,
  width,
}: {
  children: ReactNode;
  /** Override the default ~22rem width (e.g. for short blurbs). */
  width?: string;
}) {
  const [open, setOpen] = useState(false);
  const [flipLeft, setFlipLeft] = useState(false);
  const triggerRef = useRef<HTMLSpanElement | null>(null);

  // When the popover opens, flip to a left-anchored layout if the
  // trigger is in the right half of the viewport (otherwise the popover
  // overflows the right edge on narrow windows).
  useEffect(() => {
    if (!open || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    setFlipLeft(rect.left > window.innerWidth / 2);
  }, [open]);

  // Close on Escape so keyboard users can dismiss.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <span
      ref={triggerRef}
      className="info-tip"
      tabIndex={0}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onClick={(e) => {
        e.stopPropagation();
        setOpen((v) => !v);
      }}
      aria-label="More info"
    >
      <span aria-hidden="true">ⓘ</span>
      {open && (
        <span
          role="tooltip"
          className="info-tip-popover"
          style={{
            width: width ?? "22rem",
            ...(flipLeft ? { right: 0 } : { left: 0 }),
          }}
          // Block hover-leave from firing when the user mouses into the
          // popover content itself.
          onMouseEnter={() => setOpen(true)}
        >
          {children}
        </span>
      )}
    </span>
  );
}
