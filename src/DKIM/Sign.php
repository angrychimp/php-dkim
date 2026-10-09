<?php

namespace angrychimp\DKIM;

/**
 * @see DKIM
 */
require_once __DIR__.'/DKIM.php';

class Sign extends DKIM {

    /**
     * Signed when present in the message. From is mandatory (RFC 6376 5.4);
     * the rest are the usual recommended set.
     */
    protected static $_defaultHeaders = array(
        'From', 'Sender', 'Reply-To', 'Subject', 'Date', 'To', 'Cc',
        'MIME-Version', 'Content-Type', 'Content-Transfer-Encoding',
        'Message-ID',
    );

    /**
     * Returns the message with a DKIM-Signature header prepended.
     *
     * @return string
     * @throws Exception
     */
    public function sign() {
        return $this->getSignatureHeader() . "\r\n" . $this->_raw;
    }

    /**
     * Builds the DKIM-Signature header for this message.
     *
     * Required params: domain, selector, private_key (PEM string, or a
     * "file://" path). Optional: passphrase, hash (default sha256),
     * canonicalization (default relaxed/relaxed),
     * headers_to_sign (array of header names).
     *
     * @return string
     * @throws Exception
     */
    public function getSignatureHeader() {

        foreach (array('domain', 'selector', 'private_key') as $key) {
            if (empty($this->_params[$key])) {
                throw new Exception("Missing required signing parameter: $key");
            }
        }

        $hash = isset($this->_params['hash'])
            ? strtolower($this->_params['hash'])
            : 'sha256';

        // DKIM defines only rsa-sha1 and rsa-sha256; openssl would happily
        // sign with others, producing an a= no verifier should accept
        // http://tools.ietf.org/html/rfc4871#section-3.3
        if (!in_array($hash, array('sha1', 'sha256'), true)) {
            throw new Exception("Unsupported hash algorithm: $hash");
        }

        // relaxed survives the whitespace mangling that mail systems do in
        // transit; simple/simple is the RFC default but breaks far more often
        $c = isset($this->_params['canonicalization'])
            ? $this->_params['canonicalization']
            : 'relaxed/relaxed';
        if (strpos($c, '/') === false) {
            $c .= '/simple';
        }
        list($cHeaderStyle, $cBodyStyle) = explode('/', $c);

        // bh= : hash of the canonicalized body
        $bh = self::_hashBody($this->_canonicalizeBody($cBodyStyle), $hash);

        // h= : the headers we actually found, listed in the order we hash them
        // note: not 'headers', which the parent already uses to override the
        // raw header block
        $wanted = isset($this->_params['headers_to_sign'])
            ? (array)$this->_params['headers_to_sign']
            : self::$_defaultHeaders;
        $names = array();
        $toSign = array();
        foreach ($wanted as $name) {
            // a name occurring more than once is signed from the bottom of the
            // header block upwards
            // http://tools.ietf.org/html/rfc4871#section-5.4
            $found = array_reverse($this->_getHeaderFromRaw($name, 'string'));
            foreach ($found as $header) {
                $toSign[] = $header;
                $names[] = $name;
            }
        }
        if (!in_array('From', $names)) {
            throw new Exception('Cannot sign a message with no From header');
        }

        // the signature header signs itself, with an empty b= and no trailing CRLF
        $tags = sprintf(
            'v=1; a=rsa-%s; c=%s; d=%s; s=%s; q=dns/txt; t=%d; h=%s; bh=%s; b=',
            $hash, $c, $this->_params['domain'], $this->_params['selector'],
            time(), implode(':', $names), $bh
        );
        $toSign[] = 'DKIM-Signature: ' . $tags;

        $b = $this->_signatureFor($this->_canonicalizeHeader($toSign, $cHeaderStyle), $hash);

        // ponytail: only b= is folded -- it is the only tag long enough to
        // matter. Fold the whole header if a 998-char line ever shows up.
        return 'DKIM-Signature: ' . $tags . wordwrap($b, 64, "\r\n\t", true);
    }

    /**
     * RSA-signs a canonicalized header string, returns the base64 b= value.
     *
     * @param  string $str
     * @param  string $hash
     * @return string
     * @throws Exception
     */
    protected function _signatureFor($str, $hash) {

        $alg = 'OPENSSL_ALGO_' . strtoupper($hash);
        if (!defined($alg)) {
            throw new Exception("openssl_sign() does not support hash algorithm: $hash");
        }

        $passphrase = isset($this->_params['passphrase'])
            ? $this->_params['passphrase']
            : null;

        $key = openssl_pkey_get_private($this->_params['private_key'], $passphrase);
        if ($key === false) {
            throw new Exception('Unable to load private key: ' . openssl_error_string());
        }

        $signature = '';
        if (!openssl_sign($str, $signature, $key, constant($alg))) {
            throw new Exception('Unable to sign message: ' . openssl_error_string());
        }

        return base64_encode($signature);
    }
}
