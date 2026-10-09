php-dkim
========

General TODO List
-----------------

12/31/2012

*   <del>TODO: reverse engineer Perl's Mail::DKIM::Verifier package.</del> _(rk:1/2/13)_
*   <del>TODO: start on signing code</del> _(0.4.0)_
*   <del>TODO: remove debugging output</del> _(rk:1/2/13)_

1/2/2013

*   <del>TODO: 5.4 of RFC4871; Reverse-order headers to allow for multiple instances of a signed header (e.g. Cc)</del> _(0.4.0)_
*   TODO: Allow debugging flags for more verbosity
*   <del>TODO: Figure out my damn verification problem</del> _(0.4.0 — signatures now cross-check against dkimpy in both directions)_

10/9/2026

*   TODO: drop the phpseclib 1.x code path in `_signatureIsValid()`/`_hashBody()` — unreachable with phpseclib 2.x+, untested, and passes a bare base64 key to `loadKey()`
*   TODO: `l=` body length tag (deliberately unimplemented; it lets an attacker append content)
*   TODO: ed25519-sha256 signing and verification (RFC 8463)
*   TODO: `g=` granularity, `s=` service type, and the `t=y` testing flag on key records
