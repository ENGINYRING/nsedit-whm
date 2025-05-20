<?php

// Ensure config is loaded first as it contains $secret
if (file_exists(__DIR__ . '/config.inc.php')) {
    include_once(__DIR__ . '/config.inc.php');
} elseif (file_exists(dirname(__DIR__) . '/includes/config.inc.php')) {
    include_once(dirname(__DIR__) . '/includes/config.inc.php');
} else {
    // This is a critical dependency. If not found, the script cannot function.
}

// misc.inc.php and wefactauth.inc.php are included if they exist and are needed.
if (file_exists(__DIR__ . '/misc.inc.php')) {
    include_once(__DIR__ . '/misc.inc.php');
}
if (file_exists(__DIR__ . '/wefactauth.inc.php')) {
    include_once(__DIR__ . '/wefactauth.inc.php');
}


global $current_user, $secret; // $secret is from config.inc.php

$current_user = false;

// Encryption constants for OpenSSL
if (!defined('ENCRYPTION_METHOD')) {
    define('ENCRYPTION_METHOD', 'aes-256-cbc'); // AES 256-bit encryption in CBC mode
}

// session startup
function _set_current_user($username, $userid, $localauth = true, $is_admin = false, $has_csrf_token = false, $is_api = false) {
    global $current_user;

    $current_user = array(
        'username' => $username, // This is the key used internally by NSEdit for the session user's login name (typically emailaddress)
        'id' => $userid,
        'localauth' => $localauth,
        'is_admin' => (bool) $is_admin,
        'has_csrf_token' => (bool) $has_csrf_token,
        'is_api' => (bool) $is_api,
    );
}

function _check_csrf_token($user_for_token_generation) {
    global $secret, $current_user;

    $found_token = '';
    if (isset($_SERVER['HTTP_X_CSRF_TOKEN']) && $_SERVER['HTTP_X_CSRF_TOKEN']) {
        $found_token = $_SERVER['HTTP_X_CSRF_TOKEN'];
    } elseif (isset($_POST['X-CSRF-Token']) && $_POST['X-CSRF-Token']) { // Common for form submissions
        $found_token = $_POST['X-CSRF-Token'];
    } elseif (isset($_POST['csrf-token']) && $_POST['csrf-token']) { // Alternative form name
        $found_token = $_POST['csrf-token'];
    }

    $csrf_token = '';
    
    // Safely access keys from $user_for_token_generation
    $user_login_identifier = 'unknown_user_login';
    $user_id_for_csrf = '0';

    if (is_array($user_for_token_generation)) {
        $user_login_identifier = $user_for_token_generation['emailaddress'] ?? 'unknown_user_login';
        $user_id_for_csrf = $user_for_token_generation['id'] ?? '0';
    }


    if (isset($secret) && !empty($secret)) {
        $csrf_hmac_secret_key = hash_pbkdf2('sha256', 'csrf_hmac_key_for_nsedit', $secret, 1000, 32, true);
        $user_specific_part_for_csrf = $user_id_for_csrf . ":" . $user_login_identifier;
        $current_session_id = session_id();
        if (empty($current_session_id) && function_exists('get_sess_user') && get_sess_user() === null) {
            // If session_id() is empty and no user is logged in, CSRF token generation might be problematic.
            // This scenario should ideally not occur if _check_csrf_token is called only for authenticated users.
            // For robustness, generate a generic token if session_id is unavailable here.
             $csrf_token = bin2hex(openssl_random_pseudo_bytes(32)); // Fallback generic token
        } else {
            $csrf_token = hash_hmac('sha256', $current_session_id . ":" . $user_specific_part_for_csrf, $csrf_hmac_secret_key);
        }
    } else {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
        }
        $csrf_token = $_SESSION['csrf_token'];
    }

    if (!empty($found_token) && hash_equals($csrf_token, $found_token)) {
        if ($current_user) { 
            $current_user['has_csrf_token'] = true;
        }
    }

    if (!defined('CSRF_TOKEN')) {
        define('CSRF_TOKEN', $csrf_token);
    }
}

function enc_secret($message) {
    global $secret;

    if (empty($secret)) { 
        return 'b64:' . base64_encode($message);
    }

    $encryption_key = hash_pbkdf2('sha256', 'nsedit_encryption_key', $secret, 10000, 32, true);
    $hmac_key = hash_pbkdf2('sha256', 'nsedit_hmac_key', $secret, 10000, 32, true);

    $iv_length = openssl_cipher_iv_length(ENCRYPTION_METHOD);
    if ($iv_length === false) {
        error_log("NSEdit enc_secret: Could not get IV length for " . ENCRYPTION_METHOD);
        return false; 
    }
    $iv = openssl_random_pseudo_bytes($iv_length);

    $ciphertext_raw = openssl_encrypt($message, ENCRYPTION_METHOD, $encryption_key, OPENSSL_RAW_DATA, $iv);
    if ($ciphertext_raw === false) {
        error_log("NSEdit enc_secret: openssl_encrypt failed. OpenSSL errors: " . openssl_error_string());
        return false; 
    }

    $iv_plus_ciphertext = $iv . $ciphertext_raw;
    $mac = hash_hmac('sha256', $iv_plus_ciphertext, $hmac_key, true); 
    return 'enc:' . base64_encode($iv_plus_ciphertext) . ':' . base64_encode($mac);
}

function dec_secret($code) {
    global $secret;

    if (strpos($code, 'b64:') === 0) { 
        if (empty($secret)) { 
            return base64_decode(substr($code, 4));
        }
        return false; 
    }

    if (strpos($code, 'enc:') !== 0 || empty($secret)) {
        return false; 
    }

    $parts = explode(':', substr($code, 4));
    if (count($parts) !== 2) {
        return false; 
    }

    $iv_plus_ciphertext_b64 = $parts[0];
    $mac_b64 = $parts[1];

    $iv_plus_ciphertext = base64_decode($iv_plus_ciphertext_b64, true);
    $received_mac = base64_decode($mac_b64, true);

    if ($iv_plus_ciphertext === false || $received_mac === false) {
        return false; 
    }

    $encryption_key = hash_pbkdf2('sha256', 'nsedit_encryption_key', $secret, 10000, 32, true);
    $hmac_key = hash_pbkdf2('sha256', 'nsedit_hmac_key', $secret, 10000, 32, true);

    $calculated_mac = hash_hmac('sha256', $iv_plus_ciphertext, $hmac_key, true);
    if (!hash_equals($calculated_mac, $received_mac)) {
        return false; 
    }

    $iv_length = openssl_cipher_iv_length(ENCRYPTION_METHOD);
    if ($iv_length === false || strlen($iv_plus_ciphertext) < $iv_length) {
        error_log("NSEdit dec_secret: Invalid IV length or ciphertext too short.");
        return false;
    }
    
    $iv = substr($iv_plus_ciphertext, 0, $iv_length);
    $ciphertext_raw = substr($iv_plus_ciphertext, $iv_length);

    $plaintext = openssl_decrypt($ciphertext_raw, ENCRYPTION_METHOD, $encryption_key, OPENSSL_RAW_DATA, $iv);

    if ($plaintext === false) {
        error_log("NSEdit dec_secret: openssl_decrypt failed. OpenSSL errors: " . openssl_error_string());
        return false;
    }

    return $plaintext;
}


function _unset_cookie($name) {
    $is_ssl = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && $_SERVER['HTTPS'] !== false;
    setcookie($name, "", time() - 3600, "/", "", $is_ssl, true); 
}

function _store_auto_login($value) {
    $is_ssl = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && $_SERVER['HTTPS'] !== false;
    setcookie('NSEDIT_AUTOLOGIN', $value, time() + 60 * 60 * 24 * 30, "/", "", $is_ssl, true); 
}

function try_login() {
    global $secret; 

    if (isset($_POST['username']) && isset($_POST['password'])) {
        if (_try_login($_POST['username'], $_POST['password'])) { 
            if (isset($secret) && !empty($secret) && isset($_POST['autologin']) && $_POST['autologin'] == '1') {
                $autologin_data = json_encode(array(
                    'username' => $_POST['username'], // This is the emailaddress used for login
                    'password' => $_POST['password'] 
                ));
                if ($autologin_data) {
                    $encrypted_autologin = enc_secret($autologin_data);
                    if ($encrypted_autologin) {
                        _store_auto_login($encrypted_autologin);
                    } else {
                        if (function_exists('writelog')) writelog("Failed to encrypt autologin token for user: " . $_POST['username'], "SYSTEM_SESSION");
                    }
                }
            }
            return true;
        }
    }
    return false;
}

function _try_login($username_param, $password) { 
    global $wefact_api_url, $wefact_api_key; 

    if (!function_exists('valid_user') || !valid_user($username_param)) { 
        if (function_exists('writelog')) writelog("Illegal username format at login attempt: " . $username_param, "SYSTEM_AUTH");
        return false;
    }

    $do_local_auth = true; 

    if (isset($wefact_api_url) && !empty($wefact_api_url) && isset($wefact_api_key) && !empty($wefact_api_key)) {
        if (function_exists('do_wefact_auth')) {
            $wefact_auth_result = do_wefact_auth($username_param, $password); 
            if ($wefact_auth_result === false) { 
                if (function_exists('writelog')) writelog("WeFact authentication failed for user: " . $username_param, $username_param);
                return false; 
            }
            if ($wefact_auth_result === -1) { 
                if (function_exists('writelog')) writelog("WeFact auth not applicable or error for user: {$username_param}. Falling back to local.", $username_param);
            } else { 
                $do_local_auth = false; 
            }
        } else {
            if (function_exists('writelog')) writelog("WeFact configured but do_wefact_auth function not found.", "SYSTEM_CONFIG_ERROR");
        }
    }

    if ($do_local_auth) {
        if (!function_exists('do_db_auth') || !do_db_auth($username_param, $password)) { 
            if (function_exists('writelog')) writelog("Local database authentication failed for user: " . $username_param, $username_param);
            return false;
        }
    }

    $user_info_from_db = function_exists('get_user_info') ? get_user_info($username_param) : null; 
    if (!$user_info_from_db) {
        if (function_exists('writelog')) writelog("User '{$username_param}' not found in local database after auth attempt.", $username_param);
        return false;
    }

    _set_current_user($user_info_from_db['emailaddress'], $user_info_from_db['id'], $do_local_auth, (bool) ($user_info_from_db['isadmin'] ?? 0) );

    if (session_status() == PHP_SESSION_ACTIVE) {
        session_unset();
        session_destroy();
    }
    
    global $sessionname;
    session_name(isset($sessionname) && !empty($sessionname) ? $sessionname : 'NSEDIT_SESSION');
    
    $is_ssl_session = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && $_SERVER['HTTPS'] !== false;
    session_set_cookie_params([
        'lifetime' => 30 * 60, 
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? '',  
        'secure' => $is_ssl_session,
        'httponly' => true,
        'samesite' => 'Lax' 
    ]);

    if (session_start() === false) {
        if (function_exists('writelog')) writelog("Session start failed.", "SYSTEM_SESSION_ERROR");
        die('Session failure: could not start session. Check PHP session configuration and permissions.');
    }
    
    if (session_regenerate_id(true) === false) { 
         if (function_exists('writelog')) writelog("Session ID regeneration failed.", "SYSTEM_SESSION_ERROR");
    }
    
    session_unset(); 
    $_SESSION['username'] = $user_info_from_db['emailaddress']; 
    $_SESSION['userid'] = $user_info_from_db['id'];
    $_SESSION['localauth'] = $do_local_auth; 
    $_SESSION['is_admin'] = (bool) ($user_info_from_db['isadmin'] ?? 0); 
    $_SESSION['login_time'] = time(); 

    _check_csrf_token($user_info_from_db); 
    return true;
}

function _check_session() {
    global $adminapikey, $adminapiips, $secret; 

    $is_ssl_session = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' && $_SERVER['HTTPS'] !== false;
    $cookie_params = [
        'lifetime' => 30 * 60, 
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? '', 
        'secure' => $is_ssl_session,
        'httponly' => true,
        'samesite' => 'Lax'
    ];
    session_set_cookie_params($cookie_params);
    
    global $sessionname;
    session_name(isset($sessionname) && !empty($sessionname) ? $sessionname : 'NSEDIT_SESSION');

    if (isset($adminapikey) && !empty($adminapikey) && isset($adminapiips) && is_array($adminapiips) && isset($_POST['adminapikey'])) {
        if (in_array($_SERVER['REMOTE_ADDR'], $adminapiips) && hash_equals($adminapikey, $_POST['adminapikey'])) {
            _set_current_user('admin_api', 0, false, true, true, true); 
            if (!defined('CSRF_TOKEN')) define('CSRF_TOKEN', 'api_key_session'); 
            return;
        } else {
            header('HTTP/1.1 403 Forbidden');
            echo "Access Denied: Invalid API key or IP address."; 
            exit(0);
        }
    }

    if (isset($_COOKIE[session_name()])) {
        if (session_start() === false) {
            if (function_exists('writelog')) writelog("Session start failed during _check_session.", "SYSTEM_SESSION_ERROR");
            _unset_cookie(session_name()); 
            return; 
        }

        if (isset($_SESSION['username']) && isset($_SESSION['userid'])) {
            $user_info_from_db = function_exists('get_user_info') ? get_user_info($_SESSION['username']) : null;
            if (!$user_info_from_db || (int)$user_info_from_db['id'] !== (int)$_SESSION['userid']) { 
                logout(); 
            } else {
                _set_current_user($_SESSION['username'], $_SESSION['userid'], (bool)($_SESSION['localauth'] ?? true), (bool)($_SESSION['is_admin'] ?? false));
                _check_csrf_token($user_info_from_db); 
                return;
            }
        } else {
            logout();
        }
    }

    if (isset($_COOKIE['NSEDIT_AUTOLOGIN']) && isset($secret) && !empty($secret)) {
        $decrypted_data_json = dec_secret($_COOKIE['NSEDIT_AUTOLOGIN']);
        if ($decrypted_data_json) {
            $login_credentials = json_decode($decrypted_data_json, true);
            if ($login_credentials && isset($login_credentials['username']) && isset($login_credentials['password'])) {
                if (_try_login($login_credentials['username'], $login_credentials['password'])) {
                    _store_auto_login($_COOKIE['NSEDIT_AUTOLOGIN']);
                    return;
                }
            }
        }
        _unset_cookie('NSEDIT_AUTOLOGIN');
    }
}

_check_session();

function is_logged_in() {
    global $current_user;
    return (bool) $current_user && isset($current_user['username']);
}

function is_csrf_safe() {
    global $current_user;
    if (!is_logged_in()) return false; 

    if (in_array($_SERVER['REQUEST_METHOD'], ['GET', 'HEAD', 'OPTIONS', 'TRACE'])) {
        return true;
    }
    return isset($current_user['has_csrf_token']) && $current_user['has_csrf_token'] === true;
}

function is_apiuser() {
    global $current_user;
    return is_logged_in() && isset($current_user['is_api']) && $current_user['is_api'] === true;
}

function is_adminuser() {
    global $current_user;
    return is_logged_in() && isset($current_user['is_admin']) && $current_user['is_admin'] === true;
}

function get_sess_user() {
    global $current_user;
    return is_logged_in() ? $current_user['username'] : null;
}

function get_sess_userid() {
    global $current_user;
    return is_logged_in() ? $current_user['id'] : null;
}

function has_local_auth() { 
    global $current_user;
    return is_logged_in() && isset($current_user['localauth']) && $current_user['localauth'] === true;
}

function logout() {
    global $current_user, $sessionname;
    
    if (session_status() == PHP_SESSION_NONE) {
        session_name(isset($sessionname) && !empty($sessionname) ? $sessionname : 'NSEDIT_SESSION');
        @session_start(); 
    }

    $_SESSION = array(); 

    if (ini_get("session.use_cookies")) { 
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    @session_destroy();

    if (isset($_COOKIE['NSEDIT_AUTOLOGIN'])) {
        _unset_cookie('NSEDIT_AUTOLOGIN');
    }

    $current_user = false; 
}

?> 