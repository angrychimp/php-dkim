<?php

/**
 * @see DKIM
 */
require_once __DIR__.'/../DKIM.php';

class DKIM_Verify extends DKIM {

    /**
     *
     *
     */
    private $_publicKeys;

    /**
     * Validates all present DKIM signatures
     *
     * @return array
     * @throws DKIM_Exception
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
                list($newkey, $newval) = explode('=', trim($val), 2);
                unset($dkim[$key]);
                if ($newkey == '') {
                    continue;
                }
                $dkim[$newkey] = $newval;
            }

            // Verify all required values are present
            // http://tools.ietf.org/html/rfc4871#section-6.1.1
            $required = array ('v', 'a', 'b', 'bh', 'd', 'h', 's');
            foreach ($required as $key) {
                if (!isset($dkim[$key])) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "signature missing required tag: $key",
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
                    'reason' => 'incompatible version: ' . $dkim['v'],
                );
                continue;
            }
            // todo: other field validations

            // d is same or subdomain of i
            // permfail: domain mismatch
            // if no i, assume it is "@d"

            // if h does not include From,
            // permfail: From field not signed

            // if x exists and expired,
            // permfail: signature expired

            // check d= against list of configurable unacceptable domains

            // optionally require user controlled list of other required signed headers


            // Get the Public Key
            // (note: may retrieve more than one key)
            // [DG]: yes, the 'q' tag MAY be empty - fallback to default
            if ( empty($dkim['q']) ) $dkim['q'] = 'dns/txt';

            list($qType, $qFormat) = explode('/', $dkim['q']);
            $pubDns = array();
            $abort = false;
            switch ($qType) {
                case 'dns':
                    switch ($qFormat) {
                        case 'txt':
                            $this->_publicKeys[$dkim['d']] = self::fetchPublicKey($dkim['d'], $dkim['s']);

                            break;
                        default:
                            $results[$num][] = array (
                                'status' => 'permfail',
                                'reason' => 'Public key unavailable (unknown q= query format)',
                            );
                            $abort = true;
                            continue;
                            break;
                    }
                    break;
                default:
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => 'Public key unavailable (unknown q= query format)',
                    );
                    $abort = true;
                    continue;
                    break;
            }
            if ($abort === true) {
                continue;
            }

            // http://tools.ietf.org/html/rfc4871#section-6.1.3
            // build/canonicalize headers
            $headerList = array_unique(explode(':', $dkim['h']));
            $headersToCanonicalize = array();
            foreach ($headerList as $headerName) {
                $headersToCanonicalize = array_merge($headersToCanonicalize, $this->_getHeaderFromRaw($headerName, 'string'));
            }
            $headersToCanonicalize[] = 'DKIM-Signature: ' . preg_replace('/([;:]\s*)b=(.*?)(;|$)/s', '${1}b=${3}', $signature);

            // get canonicalization algorithm
            list($cHeaderStyle, $cBodyStyle) = explode('/', $dkim['c']);
            list($alg, $hash) = explode('-', $dkim['a']);

            // hash the headers
            $cHeaders = $this->_canonicalizeHeader($headersToCanonicalize, $cHeaderStyle);
            // [DG]: useless
            // $hHeaders = self::_hashBody($cHeaders, $hash);

            // canonicalize body
            $cBody = $this->_canonicalizeBody($cBodyStyle);

            // Hash/encode the body
            $bh = self::_hashBody($cBody, $hash);

            if ($bh !== $dkim['bh']) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => "Computed body hash does not match signature body hash",
                );
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
                        'reason' => " Signature Algorithm $hash does not available for openssl_verify(), key #$knum)",
                    );
                    continue;
                }
                // Compute the Verification
                // [DG]: verify canonized string, not hash !
                $vResult = self::_signatureIsValid($publicKey['p'], $dkim['b'], $cHeaders, $hash);

                if (!$vResult) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "signature did not verify ({$dkim['d']} key #$knum)",
                    );
                } else {
                    $results[$num][] = array (
                        'status' => 'pass',
                        'reason' => 'Success!',
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
            $parts = explode(';', trim($record['txt']));
            $record = array();
            foreach ($parts as $part) {
                list($key, $val) = explode('=', trim($part), 2);
                $record[$key] = $val;
            }
            $public[] = $record;
        }

        return $public;
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
            $rsa = new Crypt_RSA();
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
