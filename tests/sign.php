<?php
/**
 * Round-trip self-check: sign a message, then verify it with this library's
 * own verifier. No fixtures, no DNS -- the keypair is generated per run and
 * handed to the verifier through a fetchPublicKey() override.
 *
 * Run: php tests/sign.php
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

class StubVerify extends \angrychimp\DKIM\Verify {
    public static $p;
    public static $records;   // set to override the whole TXT record set
    public static function fetchPublicKey($domain, $selector) {
        if (self::$records !== null) {
            return self::$records;
        }
        return array(array('v' => 'DKIM1', 'k' => 'rsa', 'p' => self::$p));
    }
}
// p= is the bare base64 of the DER key, as it would appear in a TXT record
StubVerify::$p = preg_replace('/-----[^-]+-----|\s+/', '', $details['key']);

$message = "From: alice@example.com\r\n"
         . "To: bob@example.net\r\n"
         . "Subject: hello\r\n"
         . "Date: Thu, 09 Oct 2025 12:00:00 +0000\r\n"
         . "\r\n"
         . "This is a test message.\r\n";

function results($raw) {
    $v = new StubVerify($raw);
    $out = array();
    foreach ($v->validate() as $res) {
        foreach ($res as $r) $out[] = $r['status'] . ': ' . $r['reason'];
    }
    return $out;
}

function signed($message, $extra = array()) {
    global $privateKey;
    $signer = new \angrychimp\DKIM\Sign($message, $extra + array(
        'domain'      => 'example.com',
        'selector'    => 'sel',
        'private_key' => $privateKey,
    ));
    return $signer->sign();
}

$body   = 'pass: Computed body hash matches signature body hash';
$header = 'pass: Computed header hash matches signature header hash';

// a signature this library produces is one this library accepts
foreach (array('relaxed/relaxed', 'simple/simple', 'relaxed/simple', 'simple/relaxed') as $c) {
    $r = results(signed($message, array('canonicalization' => $c)));
    assert(in_array($body, $r), "body hash should verify, c=$c");
    assert(in_array($header, $r), "header hash should verify, c=$c");
    assert(preg_grep('/^permfail/', $r) === array(), "no permfail, c=$c");
}

// sha1 signatures round-trip too
$r = results(signed($message, array('hash' => 'sha1')));
assert(in_array($body, $r) && in_array($header, $r), 'sha1 should verify');

// the signature actually covers the body
$r = results(str_replace('This is a test', 'That was a test', signed($message)));
assert(!in_array($body, $r), 'tampered body must not pass the body hash');

// ...and the signed headers
$r = results(str_replace('Subject: hello', 'Subject: goodbye', signed($message)));
assert(!in_array($header, $r), 'tampered subject must not pass the header hash');

// h= lists only headers that were present
$sig = signed($message);
preg_match('/h=([^;]+);/', $sig, $m);
assert($m[1] === 'From:Subject:Date:To', "unexpected h= list: {$m[1]}");

// the shapes that break canonicalization. these are also cross-checked against
// dkimpy (an independent implementation) -- see the note at the bottom.
$hard = array(
    'folded header'  => "From: a@example.com\r\nSubject: long subject that\r\n\thas been folded\r\n\r\nbody\r\n",
    'trailing space' => "From: a@example.com\r\nSubject: ws\r\n\r\ntrailing spaces   \r\nand\ttabs\t\r\n",
    'trailing blanks'=> "From: a@example.com\r\nSubject: b\r\n\r\nbody\r\n\r\n\r\n\r\n",
    'empty body'     => "From: a@example.com\r\nSubject: e\r\n\r\n",
    'utf8 header'    => "From: a@example.com\r\nSubject: \xc3\xa9t\xc3\xa9 caf\xc3\xa9\r\n\r\nbody\r\n",
    'long body'      => "From: a@example.com\r\nSubject: l\r\n\r\n" . str_repeat("lorem ipsum\r\n", 200),
    // Mailman 3 adds Message-ID-Hash; a prefix match would sign it as a second
    // Message-ID and produce a signature nobody else accepts
    'name collision' => "From: a@example.com\r\nSubject: s\r\nMessage-ID: <x@example.com>\r\n"
                      . "Message-ID-Hash: QWERTY\r\nTo: b@example.net\r\nToken: nope\r\n\r\nbody\r\n",
);
foreach ($hard as $label => $raw) {
    foreach (array('relaxed/relaxed', 'simple/simple') as $c) {
        $r = results(signed($raw, array('canonicalization' => $c)));
        assert(in_array($body, $r), "body hash should verify: $label [$c]");
        assert(in_array($header, $r), "header hash should verify: $label [$c]");
    }
}

// a header occurring twice is signed twice, bottom-to-top (RFC 6376 5.4.2).
// the round trip below would pass either ordering as long as both sides agree,
// so also inspect the string that actually went to the signer.
class SpySign extends \angrychimp\DKIM\Sign {
    public $signedString;
    protected function _signatureFor($str, $hash) {
        $this->signedString = $str;
        return parent::_signatureFor($str, $hash);
    }
    public function canonBody($style) {
        return $this->_canonicalizeBody($style);
    }
    public function canonHeader($headers, $style) {
        return $this->_canonicalizeHeader($headers, $style);
    }
}

// a header name must match on the colon, not as a bare prefix
$collide = "From: a@example.com\r\nSubject: s\r\nMessage-ID: <x@example.com>\r\n"
         . "Message-ID-Hash: QWERTY\r\nTo: b@example.net\r\nToken: nope\r\n\r\nbody\r\n";
preg_match('/h=([^;]+);/', signed($collide), $m);
assert($m[1] === 'From:Subject:To:Message-ID', "name collision leaked into h=: {$m[1]}");
$dup = "From: a@example.com\r\nCc: first@example.net\r\nSubject: d\r\nCc: last@example.net\r\n\r\nbody\r\n";
$spy = new SpySign($dup, array('domain' => 'example.com', 'selector' => 'sel', 'private_key' => $privateKey));
preg_match('/h=([^;]+);/', $spy->getSignatureHeader(), $m);
assert($m[1] === 'From:Subject:Cc:Cc', "dup headers should appear twice in h=: {$m[1]}");
assert(
    strpos($spy->signedString, 'last@example.net') < strpos($spy->signedString, 'first@example.net'),
    'the bottom-most Cc must be hashed first'
);
foreach (array('relaxed/relaxed', 'simple/simple') as $c) {
    $r = results(signed($dup, array('canonicalization' => $c)));
    assert(in_array($header, $r), "repeated headers should verify end to end [$c]");
    assert(preg_grep('/^permfail/', $r) === array(), "no permfail on repeated headers [$c]");
}

// h= naming a header the message does not carry (oversigning, used to detect
// headers added after signing) contributes nothing to the hash
$r = results(signed($message, array('headers_to_sign' => array('From', 'Subject', 'Bcc'))));
assert(in_array($header, $r), 'oversigned absent header should still verify');

// missing required params are rejected before any crypto happens
foreach (array('domain', 'selector', 'private_key') as $missing) {
    $params = array('domain' => 'd', 'selector' => 's', 'private_key' => $privateKey);
    unset($params[$missing]);
    try {
        $s = new \angrychimp\DKIM\Sign($message, $params);
        $s->getSignatureHeader();
        assert(false, "missing $missing should throw");
    } catch (\angrychimp\DKIM\Exception $e) {
        assert(strpos($e->getMessage(), $missing) !== false, "error should name $missing");
    }
}

// DKIM defines only rsa-sha1 and rsa-sha256; openssl would sign with others
foreach (array('md5', 'sha512', 'ed25519', '') as $bad) {
    try {
        signed($message, array('hash' => $bad));
        assert(false, "hash=$bad should be rejected");
    } catch (\angrychimp\DKIM\Exception $e) {
        assert(strpos($e->getMessage(), 'Unsupported hash algorithm') === 0,
            "wrong error for hash=$bad: " . $e->getMessage());
    }
}

// a message with no From cannot be signed
try {
    signed("Subject: no sender\r\n\r\nbody\r\n");
    assert(false, 'missing From should throw');
} catch (\angrychimp\DKIM\Exception $e) {
    assert(strpos($e->getMessage(), 'From') !== false);
}

// Body canonicalization, asserted against the RFC rather than round-tripped.
// Round-tripping cannot catch these: signer and verifier share
// _canonicalizeBody(), so a bug there keeps them agreeing with each other.
// http://tools.ietf.org/html/rfc4871#section-3.4.3 and 3.4.4
$canon = array(
    // raw body                          style       expected
    array("",                            'relaxed',  ""),
    array("",                            'simple',   "\r\n"),
    array("\r\n\r\n\r\n",                'relaxed',  ""),
    array("\r\n\r\n\r\n",                'simple',   "\r\n"),
    array("body\r\n",                    'relaxed',  "body\r\n"),
    array("body\r\n\r\n\r\n",            'relaxed',  "body\r\n"),
    array("body\r\n\r\n\r\n",            'simple',   "body\r\n"),
    array("a  b  \r\n",                  'relaxed',  "a b\r\n"),
    array("a\t\tb\t\r\n",                'relaxed',  "a b\r\n"),
    array("a  b  \r\n",                  'simple',   "a  b  \r\n"),
    array("Hi.\r\n\r\nBye.\r\n\r\n\r\n", 'relaxed',  "Hi.\r\n\r\nBye.\r\n"),
);
foreach ($canon as $i => $case) {
    list($raw, $style, $want) = $case;
    $s = new SpySign("From: a@example.com\r\n\r\n" . $raw, array('body' => $raw));
    $got = $s->canonBody($style);
    assert($got === $want, sprintf(
        'canon body #%d (%s): expected %s, got %s',
        $i, $style, json_encode($want), json_encode($got)
    ));
}

// Header canonicalization, also asserted against the RFC rather than
// round-tripped, for the same reason as the body cases above.
// http://tools.ietf.org/html/rfc4871#section-3.4.1 and 3.4.2
$spy = new SpySign($message, array());
$canonH = array(
    // headers                                style      expected
    array(array('Subject: Hi'),               'relaxed', 'subject:Hi'),
    array(array('SUBJECT: Hi'),               'relaxed', 'subject:Hi'),
    array(array('Subject:   Hi   there  '),   'relaxed', 'subject:Hi there'),
    array(array("Subject: a\r\n\tb"),         'relaxed', 'subject:a b'),   // unfolded
    array(array('Subject : Hi'),              'relaxed', 'subject:Hi'),    // WSP before colon
    array(array("Subject: Hi\t"),             'relaxed', 'subject:Hi'),
    array(array('A: 1', 'B: 2'),              'relaxed', "a:1\r\nb:2"),
    array(array('NoColonHere'),               'relaxed', 'nocolonhere:'),  // must not warn
    array(array('Subject:   Hi  '),           'simple',  'Subject:   Hi  '),
    array(array('A: 1', 'B: 2'),              'simple',  "A: 1\r\nB: 2"),
);
foreach ($canonH as $i => $case) {
    list($headers, $style, $want) = $case;
    $got = $spy->canonHeader($headers, $style);
    assert($got === $want, sprintf(
        'canon header #%d (%s): expected %s, got %s',
        $i, $style, json_encode($want), json_encode($got)
    ));
}

// Public key record checks. These are the only assertions here that fail OPEN
// if they regress -- a broken check accepts a signature it should reject.
$sig = signed($message);
$reject = array(
    'no p= at all'   => array(array('v' => 'DKIM1', 'k' => 'rsa'),
                              'does not contain public-key data'),
    'revoked key'    => array(array('v' => 'DKIM1', 'k' => 'rsa', 'p' => ''),
                              'key may have been revoked'),
    'wrong version'  => array(array('v' => 'DKIM2', 'k' => 'rsa', 'p' => StubVerify::$p),
                              'version does not match'),
    'wrong key type' => array(array('v' => 'DKIM1', 'k' => 'ed25519', 'p' => StubVerify::$p),
                              'key type does not match'),
    'wrong hash alg' => array(array('v' => 'DKIM1', 'k' => 'rsa', 'h' => 'sha1', 'p' => StubVerify::$p),
                              'hash algorithm does not match'),
);
foreach ($reject as $label => $case) {
    list($record, $needle) = $case;
    StubVerify::$records = array($record);
    $r = results($sig);
    $hit = false;
    foreach ($r as $line) {
        if (strpos($line, 'permfail') === 0 && strpos($line, $needle) !== false) $hit = true;
    }
    assert($hit, "$label should permfail with \"$needle\", got: " . json_encode($r));
}
StubVerify::$records = null;

// --emit <dir> dumps the signed fixtures and the public key for the cross-check
if (isset($argv[1], $argv[2]) && $argv[1] === '--emit') {
    $dir = $argv[2];
    is_dir($dir) || mkdir($dir, 0700, true);
    file_put_contents("$dir/pub.txt", 'v=DKIM1; k=rsa; p=' . StubVerify::$p);
    $n = 0;
    $all = array('default' => $message) + $hard + array('dup-headers' => $dup);
    foreach ($all as $label => $raw) {
        foreach (array('relaxed/relaxed', 'simple/simple') as $c) {
            file_put_contents(
                sprintf('%s/%02d-%s-%s.eml', $dir, $n++, preg_replace('/\W+/', '-', $label), strtr($c, '/', '-')),
                signed($raw, array('canonicalization' => $c))
            );
        }
    }
    echo "emitted $n fixtures to $dir\n";
}

echo "ok\n";

// Cross-check against an independent implementation (this library agreeing
// with itself proved nothing -- two canonicalization bugs survived it):
//
//   pip install dkimpy
//   php tests/sign.php --emit /tmp/dkim && python3 - <<'PY'
//   import dkim, pathlib
//   d = pathlib.Path('/tmp/dkim'); txt = (d/'pub.txt').read_bytes()
//   for f in sorted(d.glob('*.eml')):
//       print(dkim.verify(f.read_bytes(), dnsfunc=lambda n, timeout=5: txt), f.name)
//   PY
