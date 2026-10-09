<?php
/**
 * Verifier hardening: malformed input, algorithm handling, multiple
 * signatures, and the checks that have to fail closed.
 *
 * The error handler below turns every PHP warning into a failure, so the
 * malformed-input cases assert "parses without complaint" as well as
 * "reaches the right verdict".
 *
 * Run: php tests/verify.php
 */

require_once __DIR__ . '/../src/DKIM/Sign.php';
require_once __DIR__ . '/../src/DKIM/Verify.php';

set_error_handler(function ($no, $str) { throw new ErrorException($str); });

$pair = openssl_pkey_new(array(
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
));
if ($pair === false) {
    fwrite(STDERR, "skip: openssl cannot generate a keypair here\n");
    exit(0);
}
openssl_pkey_export($pair, $privateKey);
$details = openssl_pkey_get_details($pair);
$publicKey = preg_replace('/-----[^-]+-----|\s+/', '', $details['key']);

class V extends \angrychimp\DKIM\Verify {
    public static $records;
    public static $verifyResult;          // override the openssl_verify outcome
    public static function fetchPublicKey($domain, $selector) {
        if (self::$records !== null) {
            return self::$records;
        }
        return array(array('v' => 'DKIM1', 'k' => 'rsa', 'p' => $GLOBALS['publicKey']));
    }
    protected static function _signatureIsValid($pub, $sig, $str, $hash = 'sha1') {
        if (self::$verifyResult !== null) {
            return self::$verifyResult;
        }
        return parent::_signatureIsValid($pub, $sig, $str, $hash);
    }
    public static function parseKeyRecord($txt) {
        return static::_parseKeyRecord($txt);
    }
}

class B extends \angrychimp\DKIM\Sign {
    public function body() { return $this->_getBodyFromRaw(); }
}

$message = "From: alice@example.com\r\nSubject: hello\r\n\r\nbody\r\n";

function signedWith($params = array()) {
    global $privateKey, $message;
    $s = new \angrychimp\DKIM\Sign($message, $params + array(
        'domain' => 'example.com', 'selector' => 'sel', 'private_key' => $privateKey,
    ));
    return $s->sign();
}

function verdicts($raw) {
    $v = new V($raw);
    $out = array();
    foreach ($v->validate() as $res) {
        foreach ($res as $r) $out[] = $r['status'] . ': ' . $r['reason'];
    }
    return $out;
}

/** Replaces the DKIM-Signature tag string of an already-signed message. */
function resign($raw, $tags) {
    return preg_replace('/^DKIM-Signature: .*?(\r\n(?![ \t]))/s', "DKIM-Signature: $tags\$1", $raw, 1);
}

function has($needle, $list) {
    foreach ($list as $line) {
        if (strpos($line, $needle) !== false) return true;
    }
    return false;
}

$PASS_HEADER = 'pass: Computed header hash matches signature header hash';

// ---------------------------------------------------------------- baseline
$signed = signedWith();
assert(has($PASS_HEADER, verdicts($signed)), 'baseline signature should verify');

// ------------------------------------------------- a signature must fail closed
// openssl_verify() returns 1, 0 or -1. -1 means an internal error, and it is
// truthy -- treating it as success would accept anything.
foreach (array(-1, 0, false) as $bad) {
    V::$verifyResult = $bad;
    $r = verdicts($signed);
    assert(!has($PASS_HEADER, $r), 'openssl_verify ' . var_export($bad, true) . ' must not pass');
    assert(has('permfail: Signature did not verify', $r), 'should permfail for ' . var_export($bad, true));
}
V::$verifyResult = 1;
assert(has($PASS_HEADER, verdicts($signed)), 'openssl_verify 1 should pass');
V::$verifyResult = null;

// ------------------------------------------------------------- required tags
$full = 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; q=dns/txt; '
      . 'h=From; bh=AAAA; b=BBBB';
foreach (array('v', 'a', 'b', 'bh', 'd', 'h', 's') as $tag) {
    $stripped = trim(preg_replace("/\b$tag=[^;]*;?\s*/", '', $full), '; ');
    $r = verdicts(resign($signed, $stripped));
    assert(has("Signature missing required tag: $tag", $r), "missing $tag should be reported");
}

// -------------------------------------------------------------- algorithms
foreach (array('ed25519-sha256', 'rsa-md5', 'rsa', 'sha256', '') as $alg) {
    $r = verdicts(resign($signed, str_replace('a=rsa-sha256', "a=$alg", $full)));
    assert(has('Unsupported signature algorithm', $r)
        || has('Signature missing required tag: a', $r), "a=$alg should be rejected");
}
// the tag is case insensitive, so an uppercase spelling is still rsa-sha256
$r = verdicts(str_replace('a=rsa-sha256', 'a=RSA-SHA256', $signed));
assert(!has('Unsupported signature algorithm', $r), 'a= should be case insensitive');

// a signature we will never accept must not cost a DNS lookup first
class Counting extends V {
    public static $hits = 0;
    public static function fetchPublicKey($domain, $selector) {
        self::$hits++;
        return parent::fetchPublicKey($domain, $selector);
    }
}
$c = new Counting(resign($signed, str_replace('a=rsa-sha256', 'a=ed25519-sha256', $full)));
$c->validate();
assert(Counting::$hits === 0, 'unsupported a= must be rejected before the key lookup');
$c = new Counting(resign($signed, str_replace('q=dns/txt', 'q=pigeon', $full)));
$c->validate();
assert(Counting::$hits === 0, 'unusable q= must be rejected before the key lookup');

// --------------------------------------------------------------------- q=
foreach (array('dns', 'dns/pigeon', 'pigeon/txt', 'x') as $q) {
    $r = verdicts(resign($signed, str_replace('q=dns/txt', "q=$q", $full)));
    assert(has('unknown q= query format', $r), "q=$q should be rejected");
}
// q= is optional and defaults to dns/txt
$r = verdicts(resign($signed, str_replace('q=dns/txt; ', '', $full)));
assert(!has('unknown q= query format', $r), 'absent q= should default to dns/txt');

// ------------------------------------------------- malformed signature tags
// none of these may raise a warning; the guards exist so they parse cleanly
$malformed = array(
    'empty segment'  => 'v=1; ; a=rsa-sha256; d=example.com; s=sel; h=From; bh=AAAA; b=BBBB',
    'bare word'      => 'v=1; garbage; a=rsa-sha256; d=example.com; s=sel; h=From; bh=AAAA; b=BBBB',
    'trailing semi'  => 'v=1; a=rsa-sha256; d=example.com; s=sel; h=From; bh=AAAA; b=BBBB;',
    'only semicolons'=> ';;;',
    'empty'          => '',
    'no tags at all' => 'not a signature',
);
foreach ($malformed as $label => $tags) {
    $r = verdicts(resign($signed, $tags));
    assert(is_array($r), "malformed signature should not blow up: $label");
}

// ------------------------------------------------------- public key records
// real records routinely end in ";", which used to read past the last tag
$records = array(
    'plain'          => array('v=DKIM1; k=rsa; p=ABC', array('v'=>'DKIM1','k'=>'rsa','p'=>'ABC')),
    'trailing semi'  => array('v=DKIM1; k=rsa; p=ABC;', array('v'=>'DKIM1','k'=>'rsa','p'=>'ABC')),
    // FWS around a tag is ignored, so values come back trimmed
    'extra spaces'   => array(' v=DKIM1 ;  k=rsa ; p=ABC ', array('v'=>'DKIM1','k'=>'rsa','p'=>'ABC')),
    'bare word'      => array('v=DKIM1; junk; p=ABC', array('v'=>'DKIM1','p'=>'ABC')),
    'base64 padding' => array('p=AB==', array('p'=>'AB==')),
    'empty'          => array('', array()),
);
foreach ($records as $label => $case) {
    list($txt, $want) = $case;
    $got = V::parseKeyRecord($txt);
    assert($got === $want, "key record '$label': got " . json_encode($got));
}

// ------------------------------------------------------ no key to verify with
// a failed TXT lookup is reported, and must not then be iterated as if it were
// a key list. The body hash verdict still stands.
V::$records = false;
$r = verdicts($signed);
assert(has('Public key unavailable (TXT record was not available)', $r), 'missing TXT reported');
assert(has('pass: Computed body hash', $r), 'body hash still checked without a key');
assert(!has($PASS_HEADER, $r), 'nothing may pass the header hash without a key');
V::$records = array();
$r = verdicts($signed);
assert(!has($PASS_HEADER, $r), 'an empty key list must not pass');
V::$records = null;

// ------------------------------------------------- multiple DKIM-Signatures
// two signatures over the SAME message, not two messages concatenated
function sigHeader($params = array()) {
    global $privateKey, $message;
    $s = new \angrychimp\DKIM\Sign($message, $params + array(
        'domain' => 'example.com', 'selector' => 'sel', 'private_key' => $privateKey,
    ));
    return $s->getSignatureHeader();
}
function statusesOf($raw) {
    $v = new V($raw);
    $out = array();
    foreach ($v->validate() as $set) {
        $lines = array();
        foreach ($set as $r) $lines[] = $r['status'] . ': ' . $r['reason'];
        $out[] = $lines;
    }
    return $out;
}
$sigA = sigHeader(array('canonicalization' => 'relaxed/relaxed'));
$sigB = sigHeader(array('canonicalization' => 'simple/simple'));

$res = statusesOf($sigA . "\r\n" . $sigB . "\r\n" . $message);
assert(count($res) === 2, 'two signatures should yield two result sets, got ' . count($res));
foreach ($res as $i => $lines) {
    assert(has($PASS_HEADER, $lines), "signature #$i should verify: " . json_encode($lines));
}

// one good, one whose body hash was tampered with: the good one must still pass
$broken = preg_replace('/bh=[^;]+;/', 'bh=AAAA;', $sigA);
$res = statusesOf($broken . "\r\n" . $sigB . "\r\n" . $message);
assert(count($res) === 2, 'mixed pair should still yield two result sets');
assert(has('permfail: Computed body hash does not match', $res[0]), 'tampered sig must fail');
assert(has($PASS_HEADER, $res[1]), 'the untouched signature must still pass');

// ------------------------------------------------------------ body handling
// a message with no blank line has no body, rather than a slice of its headers
$b = new B("From: a@example.com\r\nSubject: s\r\n", array());
assert($b->body() === '', 'headers-only message should have an empty body');
$b = new B("From: a@example.com\r\n\r\nreal body\r\n", array());
assert($b->body() === "real body\n", 'body should start after the blank line');

echo "ok\n";
