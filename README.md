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

**v0.02**
_5:36 PM 1/2/2013_

* Splitting TODOs into separate file.
* Finally got the header hash to match my expected value, based on debugging output from Mail::DKIM::Validate.
* Removed var_dump() calls
* Still doesn't verify signatures properly - not sure where to go from here.

**v0.01**
_10:55 AM 12/31/2012_
Initial commit. Most of the structure is in place, and the body hashes are validating, but I haven't been able to get the signature validation correct just yet. I must have some whitespace issue or some random public key problem.
