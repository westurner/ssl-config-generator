// sleep for any number of milliseconds
export const sleep = (milliseconds) => {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
};

// HTML-escape XML special chars: " & ' < > `
export const xmlEntities = (str) => {
  return String(str).replace(/["&'<>`]/g,
           function (x) { return '&#x'+x.codePointAt(0).toString(16)+';'; });
};

// Convert a URLSearchParams value (the second element of an `entries()`
// pair) into a tri-state checkbox value. Supports both the short
// "flag-only" form (`?hsts&ocsp`, where URLSearchParams reports the
// value as `''`) and the explicit `?hsts=true&ocsp=false` form.
//
// Tri-state mapping:
//   - undefined / null          → null   (key absent — no decision)
//   - '' (flag-only present)    → true
//   - 'true' / '1' / 'on' / 'yes'  → true   (case-insensitive)
//   - 'false' / '0' / 'off' / 'no' → false  (case-insensitive)
//   - any other non-empty string   → !!value (truthy)
//
// Returning `null` (rather than collapsing to `true`) lets callers
// distinguish "key not in the URL fragment at all" from "key present
// without a value" — useful for legacy guideline ≤ 5.7 fallbacks
// where absence and explicit "false" mean different things.
export const hashValueToBool = (value) => {
  if (value === undefined || value === null) return null;
  if (value === '') return true;
  const v = String(value).toLowerCase();
  if (v === 'true' || v === '1' || v === 'on' || v === 'yes') return true;
  if (v === 'false' || v === '0' || v === 'off' || v === 'no') return false;
  return !!value;
};
