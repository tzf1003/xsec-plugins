import type { JSX } from "preact";

export type IconName =
  | "arrow-left" | "arrow-right" | "check" | "close" | "external"
  | "filter" | "message" | "play" | "refresh" | "search" | "settings" | "trash";

const paths: Record<IconName, JSX.Element> = {
  "arrow-left": <><path d="m15 18-6-6 6-6"/><path d="M9 12h10"/></>,
  "arrow-right": <><path d="m9 18 6-6-6-6"/><path d="M5 12h10"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  close: <><path d="m6 6 12 12"/><path d="m18 6-12 12"/></>,
  external: <><path d="M15 3h6v6"/><path d="m10 14 11-11"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></>,
  filter: <path d="M4 5h16l-6 7v5l-4 2v-7Z"/>,
  message: <><path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4Z"/><path d="M12 7v8M8 11h8"/></>,
  play: <path d="m8 5 11 7-11 7Z"/>,
  refresh: <><path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/></>,
  search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
  settings: <><path d="M4 6h16M7 12h10M10 18h4"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="12" cy="18" r="2"/></>,
  trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14"/><path d="M10 11v6M14 11v6"/></>,
};

/** Render the icon component. */
export function Icon({ name, size = 15 }: { name: IconName; size?: number }) {
  return <svg className="x-icon" viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
