php-dkim
========

**Finally, a PHP5 class for not just signing, but _verifying_ DKIM signatures.**

Requirements
------------
Currently this package requires PHP 5.1.2 or greater (or PECL `hash` >= 1.1), which provides the `hash()` function.

Also required, at least one of the following present alongside your PHP installation.

* [openssl](http://us1.php.net/manual/en/openssl.installation.php)
* [phpseclib](http://phpseclib.sourceforge.net/)

At least one of those packages must be present in order to compute the RSA signature verification.

Usage
-----
&lt;pending&gt;


Changelog
---------

**v0.2.1**
_11:28 AM 3/3/2016_
* Fixed index variable issue (#7)
* Addressed validation issue when public key record did not have public-key data (#7)
* Minor version numbering corrections
* Dropped old copyright info for as-yet-still-empty Sign code
* Fixed new-line trimming issue (potentially causing verification problems?) (#7)

**v0.2**
_5:36 PM 1/2/2013_

* Splitting TODOs into separate file.
* Finally got the header hash to match my expected value, based on debugging output from Mail::DKIM::Validate.
* Removed var_dump() calls
* Still doesn't verify signatures properly - not sure where to go from here.

**v0.1**
_10:55 AM 12/31/2012_
Initial commit. Most of the structure is in place, and the body hashes are validating, but I haven't been able to get the signature validation correct just yet. I must have some whitespace issue or some random public key problem.
