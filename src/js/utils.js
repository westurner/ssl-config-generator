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
// pair) into a boolean checkbox state. Supports both the short
// "flag-only" form (`?hsts&ocsp`, where URLSearchParams reports the
// value as `''`) and the explicit `?hsts=true&ocsp=false` form, plus
// the absent / `undefined` case (treated as "key present" → true).
//
// Truthy: undefined, '' (flag-only), 'true', '1', 'on', 'yes' (case-insensitive)
// Falsy:  'false', '0', 'off', 'no' (case-insensitive)
// Anything else falls back to `!!value` (so a stray non-empty string
// is truthy, matching how HTML checkboxes treat any non-empty value).
export const hashValueToBool = (value) => {
  if (value === undefined || value === null || value === '') return true;
  const v = String(value).toLowerCase();
  if (v === 'true' || v === '1' || v === 'on' || v === 'yes') return true;
  if (v === 'false' || v === '0' || v === 'off' || v === 'no') return false;
  return !!value;
};
