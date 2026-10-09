<?php

namespace angrychimp\DKIM;

/**
 * @see DKIM
 */
require_once __DIR__.'/DKIM.php';

class Verify extends DKIM {

    /**
     *
     *
     */
    private $_publicKeys;

    /**
     * Validates all present DKIM signatures
     *
     * @return array
     * @throws Exception
     */
    public function validate() {

        $results = array();

        // find the present DKIM signatures
        $signatures = $this->_getHeaderFromRaw('DKIM-Signature');

        if(!isset($signatures['DKIM-Signature']))
            return $results;

        $signatures = $signatures['DKIM-Signature'];

        // Validate the Signature Header Field
        $pubKeys = array();
        foreach ($signatures as $num => $signature) {

            $dkim = preg_replace('/\s+/s', '', $signature);
            $dkim = explode(';', trim($dkim));
            foreach ($dkim as $key => $val) {
                $tag = explode('=', trim($val), 2);
                unset($dkim[$key]);
                // a segment with no "=" is not a tag; a trailing ";" yields one
                if (count($tag) < 2 || $tag[0] === '') {
                    continue;
                }
                $dkim[$tag[0]] = $tag[1];
            }

            // Verify all required values are present
            // http://tools.ietf.org/html/rfc4871#section-6.1.1
            $required = array ('v', 'a', 'b', 'bh', 'd', 'h', 's');
            foreach ($required as $key) {
                if (!isset($dkim[$key])) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Signature missing required tag: $key",
                    );
                    continue;
                }
            }
            // abort if we have any errors at this point
            if (!empty($results[$num])) {
                continue;
            }

            if ($dkim['v'] != 1) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => 'Incompatible version: ' . $dkim['v'],
                );
                continue;
            }
            // rsa-sha1 and rsa-sha256 are the only algorithms DKIM defines for
            // this key type; ed25519-sha256 (RFC 8463) is not supported here.
            // Without this, an a= naming any other algorithm still reached
            // openssl_verify() as RSA. Checked before the DNS lookup below so
            // a bogus a= costs no network traffic.
            // http://tools.ietf.org/html/rfc4871#section-3.3
            if (!in_array(strtolower($dkim['a']), array('rsa-sha1', 'rsa-sha256'), true)) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => 'Unsupported signature algorithm: ' . $dkim['a'],
                );
                continue;
            }
            list($alg, $hash) = explode('-', strtolower($dkim['a']));

            // todo: other field validations

            // d is same or subdomain of i
            // permfail: domain mismatch
            // if no i, assume it is "@d"

            // if h does not include From,
            // permfail: From field not signed

            // if x exists and expired,
            // permfail: signature expired
            if (isset($dkim['x'])) {
                // RFC 6376 3.5: x= MUST be greater than t= if both are present
                if (isset($dkim['t']) && (int)$dkim['x'] <= (int)$dkim['t']) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => 'Signature expiration (x=) not greater than timestamp (t=)',
                    );
                    continue;
                }
                if ((int)$dkim['x'] < time()) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => 'Signature expired',
                    );
                    continue;
                }
            }

            // check d= against list of configurable unacceptable domains

            // optionally require user controlled list of other required signed headers


            // Get the Public Key
            // (note: may retrieve more than one key)
            // [DG]: yes, the 'q' tag MAY be empty - fallback to default
            if ( empty($dkim['q']) ) $dkim['q'] = 'dns/txt';

            // dns/txt is the only query method DKIM defines, so anything else
            // (including a q= with no "/") is unusable
            // http://tools.ietf.org/html/rfc4871#section-3.5
            if (strtolower($dkim['q']) !== 'dns/txt') {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => 'Public key unavailable (unknown q= query format)',
                );
                continue;
            }

            $this->_publicKeys[$dkim['d']] = static::fetchPublicKey($dkim['d'], $dkim['s']);
            if (!$this->_publicKeys[$dkim['d']]) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => 'Public key unavailable (TXT record was not available)',
                );
            }

            // http://tools.ietf.org/html/rfc4871#section-6.1.3
            // build/canonicalize headers
            // http://tools.ietf.org/html/rfc4871#section-5.4
            // a name repeated in h= refers to a further instance of that header
            // each time, taken from the bottom of the header block upwards
            $headersToCanonicalize = array();
            $instances = array();
            foreach (explode(':', $dkim['h']) as $headerName) {
                $headerName = trim($headerName);
                $key = strtolower($headerName);
                if (!isset($instances[$key])) {
                    $instances[$key] = array_reverse($this->_getHeaderFromRaw($headerName, 'string'));
                }
                // h= may name a header more often than the message carries it
                // (or not carry it at all); those contribute nothing to the hash
                if (!empty($instances[$key])) {
                    $headersToCanonicalize[] = array_shift($instances[$key]);
                }
            }
            $headersToCanonicalize[] = 'DKIM-Signature: ' . preg_replace('/([;:]\s*)b=(.*?)(;|$)/s', '${1}b=${3}', $signature);

            // get canonicalization algorithm
            // c= is optional and defaults to simple/simple; a lone algorithm
            // means the body half is "simple" (RFC 6376 3.5)
            if ( empty($dkim['c']) ) $dkim['c'] = 'simple/simple';
            if ( strpos($dkim['c'], '/') === false ) $dkim['c'] .= '/simple';

            list($cHeaderStyle, $cBodyStyle) = explode('/', $dkim['c']);

            // hash the headers
            $cHeaders = $this->_canonicalizeHeader($headersToCanonicalize, $cHeaderStyle);
            // [DG]: useless
            // $hHeaders = self::_hashBody($cHeaders, $hash);

            // canonicalize body
            $cBody = $this->_canonicalizeBody($cBodyStyle);

            // Hash/encode the body
            $bh = self::_hashBody($cBody, $hash);

            if ($bh === $dkim['bh']) {
                $results[$num][] = array (
                    'status' => 'pass',
                    'reason' => 'Computed body hash matches signature body hash',
                );
            } else {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => "Computed body hash does not match signature body hash",
                );
            }

            // the TXT lookup above may have failed, which was already reported.
            // The body hash result still stands, but there is no key to check
            // the signature against
            if (empty($this->_publicKeys[$dkim['d']])) {
                continue;
            }

            // Iterate over keys
            foreach ($this->_publicKeys[$dkim['d']] as $knum => $publicKey) {
                // Validate key

                // confirm that required fields are present
                if (!isset($publicKey['p'])) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key record does not contain public-key data ({$dkim['d']} key #$knum)",
                    );
                    continue;
                } else {
                    // verify that public key data is not empty
                    if (empty($publicKey['p'])) {
                        $results[$num][] = array (
                            'status' => 'permfail',
                            'reason' => "Public key record public-key data is emtpy; key may have been revoked ({$dkim['d']} key #$knum)",
                        );
                        continue;
                    }
                }

                // confirm that pubkey version matches sig version (v=)
                // [DG]: may be missed
                if (isset($publicKey['v']) && $publicKey['v'] !== 'DKIM' . $dkim['v']) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key version does not match signature version ({$dkim['d']} key #$knum)",
                    );
                }

                // confirm that published hash matches sig hash (h=)
                if (isset($publicKey['h']) && $publicKey['h'] !== $hash) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key hash algorithm does not match signature hash algorithm ({$dkim['d']} key #$knum)",
                    );
                }

                // confirm that the key type matches the sig key type (k=)
                if (isset($publicKey['k']) && $publicKey['k'] !== $alg) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key type does not match signature key type ({$dkim['d']} key #$knum)",
                    );
                }

                // See http://tools.ietf.org/html/rfc4871#section-3.6.1
                // verify pubkey granularity (g=)

                // verify service type (s=)

                // check testing flag


                // [DG]: is $hash algo available for openssl_verify ?
                if ( !class_exists('Crypt_RSA') && !defined('OPENSSL_ALGO_'.strtoupper($hash)) ) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Signature Algorithm $hash does not available for openssl_verify(), key #$knum)",
                    );
                    continue;
                }
                // Compute the Verification
                // [DG]: verify canonized string, not hash !
                $vResult = static::_signatureIsValid($publicKey['p'], $dkim['b'], $cHeaders, $hash);

                // openssl_verify() returns 1, 0 or -1, and -1 (an internal
                // error) is truthy -- only an explicit 1 counts as a pass
                if ($vResult !== true && $vResult !== 1) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Signature did not verify ({$dkim['d']} key #$knum)",
                    );
                } else {
                    $results[$num][] = array (
                        'status' => 'pass',
                        'reason' => 'Computed header hash matches signature header hash',
                    );
                }
            }

        }

        return $results;
    }

    /**
     *
     *
     */
    public static function fetchPublicKey($domain, $selector) {
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        $pubDns = dns_get_record($host, DNS_TXT);

        if ($pubDns === false) {
            return false;
        }

        $public = array();
        foreach ($pubDns as $record) {
            // [DG]: long key may be split to parts
            if ( isset($record['entries']) ) $record['txt'] = implode('',$record['entries']);
            if ( !isset($record['txt']) ) continue;
            $public[] = static::_parseKeyRecord($record['txt']);
        }

        return $public;
    }

    /**
     * Splits a DKIM key TXT record into its tags.
     *
     * @param  string $txt
     * @return array
     */
    protected static function _parseKeyRecord($txt) {
        $record = array();
        foreach (explode(';', trim($txt)) as $part) {
            // records commonly end in ";", leaving an empty segment with no "="
            $tag = explode('=', trim($part), 2);
            if (count($tag) < 2 || $tag[0] === '') {
                continue;
            }
            $record[$tag[0]] = $tag[1];
        }
        return $record;
    }

    /**
     *
     *
     */
    protected static function _signatureIsValid($pub, $sig, $str, $hash='sha1') {
        // Convert key back into PEM format
        $key = sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", wordwrap($pub, 64, "\n", true));

        // prefer Crypt_RSA
        // http://phpseclib.sourceforge.net
        // [DG]: X3 how Crypt_RSA works, skip
        if (class_exists('Crypt_RSA')) {
            $rsa = new \Crypt_RSA();
            $rsa->setHash($hash);
            $rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
            $rsa->loadKey($pub);
            return $rsa->verify($str, base64_decode($sig));
        } else {
            // $pubkeyid = openssl_get_publickey($key);
            $signature_alg = constant('OPENSSL_ALGO_'.strtoupper($hash));
            return openssl_verify($str, base64_decode($sig), $key, $signature_alg);
        }

    }

}
