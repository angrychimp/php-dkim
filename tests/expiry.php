<?php
/**
 * Self-check for DKIM-Signature x= (expiration) handling.
 * Run: php tests/expiry.php
 */

require_once __DIR__ . '/../src/DKIM/Verify.php';

// any warning (e.g. undefined array key "t") is a failure
set_error_handler(function ($no, $str) { throw new ErrorException($str); });

function reasons($tags, $q = '') {
    $sig = 'v=1; a=rsa-sha256; d=example.com; s=sel; h=from; '
         . 'bh=AAAA; b=BBBB; ' . $q . $tags;
    $raw = "From: a@example.com\r\nDKIM-Signature: $sig\r\n\r\nbody\r\n";
    $v = new \angrychimp\DKIM\Verify($raw);
    $out = array();
    foreach ($v->validate() as $res) {
        foreach ($res as $r) $out[] = $r['reason'];
    }
    return $out;
}

$older = time() - 7200;
$past = time() - 3600;
$future = time() + 3600;

// expired signature is rejected
assert(in_array('Signature expired', reasons("t=$older; x=$past")));

// x= must be greater than t= when both present
assert(in_array(
    'Signature expiration (x=) not greater than timestamp (t=)',
    reasons("t=$future; x=$past")
));

// x= without t= must not warn, and must not be treated as expired (PR #14)
$r = reasons("x=$future");
assert(!in_array('Signature expired', $r));
assert(!in_array('Signature expiration (x=) not greater than timestamp (t=)', $r));

// an unusable q= aborts this signature outright -- the q= permfail must be the
// only result, i.e. execution never falls through to body hashing
$bad = 'Public key unavailable (unknown q= query format)';
assert(reasons("x=$future", 'q=dns/pigeon; ') === array($bad));  // inner switch
assert(reasons("x=$future", 'q=pigeon/txt; ') === array($bad));  // outer switch

echo "ok\n";
