php-dkim
========

**Finally, a PHP5 class for not just signing, but _verifying_ DKIM signatures.**

Requirements
------------
PHP 5.3 or greater (namespaces), with the [openssl](http://us1.php.net/manual/en/openssl.installation.php)
and [hash](http://php.net/manual/en/book.hash.php) extensions. CI covers PHP 7.4 through 8.4.

A legacy code path will use [phpseclib](http://phpseclib.sourceforge.net/) 1.x if its
global `Crypt_RSA`/`Crypt_Hash` classes happen to be loaded. That path is untested and
not recommended; phpseclib 2.x and later are namespaced and never trigger it.

Usage
-----

### Verifying

```php
$verifier = new angrychimp\DKIM\Verify($rawMessage);
foreach ($verifier->validate() as $num => $results) {
    foreach ($results as $result) {
        echo $result['status'], ': ', $result['reason'], "\n";   // pass | permfail
    }
}
```

Each `DKIM-Signature` header in the message gets its own result set. The public key is
fetched from DNS; a message is only verified if both the body hash and the header hash
pass.

### Signing

```php
$signer = new angrychimp\DKIM\Sign($rawMessage, array(
    'domain'      => 'example.com',
    'selector'    => 'mail',
    'private_key' => file_get_contents('/path/to/private.pem'),  // or 'file:///path/to/private.pem'
));
echo $signer->sign();                   // the message with DKIM-Signature prepended
echo $signer->getSignatureHeader();     // just the header
```

Optional parameters:

| Parameter | Default | Notes |
|---|---|---|
| `passphrase` | none | for an encrypted private key |
| `hash` | `sha256` | `sha1` or `sha256` |
| `canonicalization` | `relaxed/relaxed` | `simple` survives transit far less often |
| `headers_to_sign` | a recommended set | array of header names; `From` is mandatory |

Signatures produced here are checked against [dkimpy](https://pypi.org/project/dkimpy/)
in CI, in both directions, so they interoperate rather than merely round-tripping.

### Compatibility

The pre-0.4.0 global class names (`DKIM_Sign`, `DKIM_Verify`, `DKIM_Exception`) still work
as aliases when the package is loaded through Composer. They will be removed in a future
major release.


Changelog
---------

**v0.4.0**

_Breaking release._ Classes are namespaced and the signing half of the library finally exists.

* **Breaking:** moved to PSR-4 under `angrychimp\DKIM\`. `DKIM_Sign` → `Sign`, `DKIM_Verify` →
  `Verify`, `DKIM_Exception` → `Exception`. The old global names remain as aliases via Composer
  and will be dropped in a future major release.
* **Signing implemented**, open since 2012. Supports relaxed/simple canonicalization, sha1/sha256,
  configurable signed-header sets, and RFC 6376 5.4.2 bottom-to-top ordering for repeated headers.
* **Security:** `openssl_verify()` returns `-1` on internal error, which is truthy — an errored
  verification was being reported as a pass. It now requires an explicit success.
* **Security:** `a=` was never validated, so a signature naming any algorithm (e.g. `ed25519-sha256`)
  was still verified as RSA. Restricted to `rsa-sha1`/`rsa-sha256`, and checked before the DNS
  lookup so a bogus `a=` costs no network traffic.
* Fixed header lookup matching on a bare prefix: `Message-ID` also matched `Message-ID-Hash`
  (which Mailman 3 adds), silently producing signatures no other implementation accepts.
* Fixed relaxed canonicalization of an empty body, which emitted `CRLF` instead of a null input.
  This affected verification too, rejecting valid signatures on empty-bodied mail.
* Fixed `h=` handling for a header name listed more than once; it was deduplicated, so messages
  with repeated headers could never verify.
* Fixed signature expiration: `x=` was never enforced, and reading `t=` unguarded errored when
  `x=` appeared alone.
* `c=` now defaults to `simple/simple` and tolerates a lone algorithm, per RFC 6376 3.5.
* Hardened parsing against malformed input: signature tags and key records with no `=` or a
  trailing `;`, `q=` with no `/`, headers with no colon, failed DNS lookups, and messages with
  no blank line (whose body was previously read from the middle of a header).
* Added test suites covering signing, verification, and tag handling, plus GitHub Actions
  running them on PHP 7.4–8.4 and cross-checking signatures against dkimpy in both directions.

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
