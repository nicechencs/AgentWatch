/**
 * Route module for `/s/:sid/findings` — re-exports `FindingsPage` so
 * `@tanstack/react-router` can code-split it alongside the other session pages.
 */
export { FindingsPage as default } from "@/features/findings/FindingsPage";
