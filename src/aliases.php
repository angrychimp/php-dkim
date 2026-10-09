<?php

/**
 * Backwards compatibility for the pre-0.3.0 global class names.
 *
 * These cannot live alongside their classes: Composer only loads a class file
 * when that class is requested, and nothing requests "DKIM_Verify" any more.
 * Hence composer.json's autoload.files entry, which loads this unconditionally.
 *
 * Drop this file (and that entry) in the next major version.
 */

require_once __DIR__.'/DKIM/Sign.php';
require_once __DIR__.'/DKIM/Verify.php';

class_alias('angrychimp\DKIM\DKIM', 'DKIM');
class_alias('angrychimp\DKIM\Exception', 'DKIM_Exception');
class_alias('angrychimp\DKIM\Sign', 'DKIM_Sign');
class_alias('angrychimp\DKIM\Verify', 'DKIM_Verify');
