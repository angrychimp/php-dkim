<?php

namespace angrychimp\DKIM;

/**
 * @see phpseclib/Crypt/RSA
 */
// require_once 'phpseclib/Crypt/RSA.php';

/**
 * @see phpseclib/Crypt/Hash
 * @link http://phpseclib.sourceforge.net
 */
// require_once 'phpseclib/Crypt/Hash.php';

define('PHPSECLIB_USE_EXCEPTIONS', true);

require_once __DIR__.'/Exception.php';

abstract class DKIM {
    
    /**
     *
     *
     */
    protected $_raw;
    
    /**
     *
     *
     */
    protected $_message;
    
    /**
     *
     *
     */
    protected $_params;
    
    /**
     * Initializes required variables and creates/returns a DKIM object
     *
     * @param  string $rawMessage
     * @return DKIM
     * @throws Exception
     */
    public function __construct($rawMessage='', $params=array()) {
        
        $this->_raw = $rawMessage;
        if (!$this->_raw) {
            throw new Exception('No message content provided');
        }
        
        $this->_params = $params;
        
        // to-do: validate RFC-2822 compatible message string
        
        return $this;
    }
    
    /**
     * Canonicalizes a header in either "relaxed" or "simple" modes.
     * Requires an array of headers (header names are part of array values)
     *
     * @param  array $headers
     * @param  string $style
     * @return string
     * @throws Exception
     */
    protected function _canonicalizeHeader($headers=array(), $style="simple") {
        $headers = (array)$headers;
        if (sizeof($headers) == 0) {
            throw new Exception("Attempted to canonicalize empty header array");
        }
        
        $cHeader = '';
        switch ($style) {
            case 'simple':
                $cHeader = implode("\r\n", $headers);
                break;
            case 'relaxed':
            default:
                
                $new = array();
                foreach ($headers as $header) {
                    // split off header name; a line with no colon is not a
                    // header field, but drop it and the hash silently changes
                    $parts = explode(':', $header, 2);
                    $name = $parts[0];
                    $val = isset($parts[1]) ? $parts[1] : '';

                    // lowercase field name
                    $name = trim(strtolower($name));
                    
                    // unfold header values and reduce whitespace
                    $val = trim(preg_replace('/\s+/s', ' ', $val));
                    
                    $new[] = "$name:$val";
                }
                $cHeader = implode("\r\n", $new);
                
                break;
        }
        
        return $cHeader;
    }
    
    /**
     * Canonicalizes a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param  string $body
     * @param  string $style
     * @param  int $length
     * @return string
     * @throws Exception
     */
    protected function _canonicalizeBody($style='simple', $length=-1) {
        
        $cBody = $this->_getBodyFromRaw();

        // [DG]: mangle newlines
        $cBody = str_replace("\r\n","\n",$cBody);
        switch ($style) {
            case 'relaxed':
            default:
                // http://tools.ietf.org/html/rfc4871#section-3.4.4
                // strip whitespace off end of lines &
                // replace whitespace strings with single whitespace
                $cBody = preg_replace('/[ \t]+$/m', '', $cBody);
                $cBody = preg_replace('/[ \t]+/m', ' ', $cBody);
                
                // also perform rules for "simple" canonicalization
                
            case 'simple':
                // http://tools.ietf.org/html/rfc4871#section-3.4.3
                // remove any trailing empty lines
                $cBody = preg_replace('/\n+$/s', '', $cBody);
                break;
        }
        $cBody = str_replace("\n","\r\n",$cBody);

        // "simple" always ends in a single CRLF, even for an empty body, but
        // "relaxed" canonicalizes an empty body to a null input
        // http://tools.ietf.org/html/rfc4871#section-3.4.3 and 3.4.4
        if ($cBody !== '' || $style == 'simple') {
            $cBody .= "\r\n";
        }

        return ($length > 0) ? substr($cBody, 0, $length) : $cBody;
    }
    
    /**
     *
     *
     */
    protected function _getHeaderFromRaw($headerKey, $style='array') {
        
        $raw = (isset($this->_params['headers'])) ?
              str_replace("\r", '', $this->_params['headers'])
            : str_replace("\r", '', $this->_raw);
        $lines = explode("\n", $raw);
        $rawHeaders = array();
        $headerVal = array();
        $counter = 0;
        $on = false;
        foreach ($lines as $line) {
            if ($on === true) {
                if (preg_match('/^\w/', $line) !== 0 || trim($line) == '') {
                    // new header is starting or end of headers
                    $on = false;
                    switch ($style) {
                        case 'array':
                        default:
                            list($key, $val) = explode(':', implode("\r\n", $headerVal), 2);
                            $rawHeaders[$headerKey][$counter] = trim($val);
                            break;
                        case 'string':
                            $rawHeaders[$counter] = implode("\r\n", $headerVal);
                            break;
                    }
                    $headerVal = array();
                    $counter++;
                } else {
                    $headerVal[] = $line;
                }
            }
            // the colon is required: a bare prefix match pulls in unrelated
            // headers, e.g. "Message-ID" would also match "Message-ID-Hash".
            // WSP before the colon is obsolete syntax but still legal
            if (preg_match('/^'.preg_quote($headerKey, '/').'\s*:/i', $line)) {
                $on = true;
                $headerVal[] = $line;
            }
            
            if (trim($line) == '') {
                break;
            }
        }
        
        return $rawHeaders;
        
    }
    
    /**
     *
     *
     */
    protected function _getBodyFromRaw($style='string') {
        
        if (isset($this->_params['body'])) {
            return (string)$this->_params['body'];
        }
        
        $raw = str_replace("\r\n", "\n", $this->_raw);

        // without a blank line there is no body at all; strpos() returning
        // false here used to read from offset 2, i.e. the middle of a header
        $split = strpos($raw, "\n\n");

        return $split === false ? '' : substr($raw, $split + 2);
        
    }
    
    /**
     *
     *
     */
    protected static function _hashBody($body, $method='sha1') {
        
        // prefer to use phpseclib
        // http://phpseclib.sourceforge.net
        if (class_exists('Crypt_Hash')) {
            $hash = new \Crypt_Hash($method);
            return base64_encode($hash->hash($body));
        } else {
            // try standard PHP hash function
            return base64_encode(hash($method, $body, true));
        }
        
    }
}
