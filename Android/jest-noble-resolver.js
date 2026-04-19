/**
 * Custom Jest resolver for @noble/* and @scure/* packages.
 * These packages use "exports" field with .js suffixes in their package.json,
 * which Jest's default resolver doesn't handle well.
 * This resolver tries the original path first, and if it fails, appends .js.
 */
const path = require('path');

const NOBLE_SCURE_RE = /^@(noble|scure)\//;

module.exports = (request, options) => {
  // Only intercept @noble/* and @scure/* subpath imports
  if (NOBLE_SCURE_RE.test(request) && request.includes('/')) {
    // If request already ends with .js, try default first
    if (request.endsWith('.js')) {
      try {
        return options.defaultResolver(request, options);
      } catch (_e) { /* fall through */ }
    }
    // Try appending .js for subpath imports like @noble/hashes/sha2 → @noble/hashes/sha2.js
    try {
      return options.defaultResolver(request + '.js', options);
    } catch (_e) { /* fall through */ }
  }
  return options.defaultResolver(request, options);
};
