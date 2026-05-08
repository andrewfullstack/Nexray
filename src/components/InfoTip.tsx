import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useIntl } from "react-intl";

interface PopoverCoords {
  /** Pixel value for `top` in fixed coords. */
  top: number;
  /** Anchor edge in fixed coords. When `flipLeft`, this is the *right*
   *  edge of the popover (so it grows leftward); otherwise it's the
   *  *left* edge (so it grows rightward). */
  edge: number;
  flipLeft: boolean;
}

/// Hover/focus-activated tooltip used on the ⓘ icons next to features
/// like System proxy and TUN mode. Native `title=` attributes drop
/// formatting and word-wrap awkwardly; this gives us a styled popover
/// with multi-line content while staying keyboard-accessible.
///
/// The popover is rendered via a portal into `document.body` and uses
/// `position: fixed`. That's needed because every `.card` enables
/// `backdrop-filter`, which creates a stacking context — without the
/// portal a tall popover gets occluded by sibling cards rendered later
/// in the DOM (the symptom: System proxy / TUN tooltips appearing
/// behind the speed + egress cards on Home).
export function InfoTip({
  children,
  width,
}: {
  children: ReactNode;
  /** Override the default ~22rem width (e.g. for short blurbs). */
  width?: string;
}) {
  const intl = useIntl();
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState<PopoverCoords | null>(null);
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const popoverRef = useRef<HTMLSpanElement | null>(null);
  // Delay before a hover opens the popover. Prevents accidental
  // hover-throughs (cursor crossing the ⓘ on its way to another
  // control) from flashing a tooltip. Keyboard focus and explicit
  // clicks bypass the delay — they're deliberate signals.
  const hoverOpenTimer = useRef<number | null>(null);

  const cancelHoverOpen = () => {
    if (hoverOpenTimer.current !== null) {
      window.clearTimeout(hoverOpenTimer.current);
      hoverOpenTimer.current = null;
    }
  };

  // Cleanup any pending hover-open when the component unmounts.
  useEffect(
    () => () => {
      cancelHoverOpen();
    },
    [],
  );

  // Measure the trigger when the popover opens, and re-measure on
  // scroll / resize so the popover sticks to the trigger rather than
  // floating away. `scroll` uses capture so we catch nested scroll
  // containers too (the page itself doesn't scroll but cards might).
  useEffect(() => {
    if (!open) {
      setCoords(null);
      return;
    }
    const measure = () => {
      const el = triggerRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const flipLeft = rect.left > window.innerWidth / 2;
      setCoords({
        top: rect.bottom + 6,
        edge: flipLeft ? window.innerWidth - rect.right : rect.left,
        flipLeft,
      });
    };
    measure();
    window.addEventListener("scroll", measure, true);
    window.addEventListener("resize", measure);
    return () => {
      window.removeEventListener("scroll", measure, true);
      window.removeEventListener("resize", measure);
    };
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
      onMouseEnter={() => {
        cancelHoverOpen();
        hoverOpenTimer.current = window.setTimeout(() => {
          setOpen(true);
          hoverOpenTimer.current = null;
        }, 1000);
      }}
      onMouseLeave={() => {
        cancelHoverOpen();
        setOpen(false);
      }}
      onFocus={() => {
        // Keyboard focus is deliberate — show immediately.
        cancelHoverOpen();
        setOpen(true);
      }}
      onBlur={() => {
        cancelHoverOpen();
        setOpen(false);
      }}
      onClick={(e) => {
        // Explicit click → instant toggle. Cancel any pending hover-
        // open so the click result isn't undone a moment later.
        e.stopPropagation();
        cancelHoverOpen();
        setOpen((v) => !v);
      }}
      aria-label={intl.formatMessage({ id: "common.more_info" })}
    >
      <span aria-hidden="true">ⓘ</span>
      {open &&
        coords &&
        createPortal(
          <span
            ref={popoverRef}
            role="tooltip"
            className="info-tip-popover"
            style={{
              position: "fixed",
              top: coords.top,
              ...(coords.flipLeft
                ? { right: coords.edge }
                : { left: coords.edge }),
              width: width ?? "22rem",
            }}
            // Keep open while hovering the popover content itself, so
            // users can scroll its body or copy text without it
            // disappearing. The trigger's onMouseLeave still fires when
            // the cursor first crosses into here, but onMouseEnter on
            // the popover re-asserts open in the same tick.
            onMouseEnter={() => setOpen(true)}
            onMouseLeave={() => setOpen(false)}
          >
            {children}
          </span>,
          document.body,
        )}
    </span>
  );
}
