<?php

// Ensure config.inc.php is included first.
// The include at the top of zones.php (and other main files) should handle this,
// but including it here directly ensures it's available if misc.inc.php is ever included standalone.
if (file_exists(__DIR__ . '/config.inc.php')) {
    include_once(__DIR__ . '/config.inc.php');
} elseif (file_exists(dirname(__DIR__) . '/includes/config.inc.php')) { // If misc.inc.php is in 'includes'
    include_once(dirname(__DIR__) . '/includes/config.inc.php');
}


$blocklogin = FALSE;
$errormsg = ''; // Initialize errormsg

// WHM API Configuration Checks
// These variables are expected to be defined in config.inc.php
if (!isset($whm_host) || empty($whm_host) || $whm_host == 'your_whm_server.example.com') {
    $errormsg = 'You need to configure your settings for the WHM API: $whm_host is missing or not set.';
    $blocklogin = TRUE;
} elseif (!isset($whm_port) || empty($whm_port)) {
    $errormsg = 'You need to configure your settings for the WHM API: $whm_port is missing.';
    $blocklogin = TRUE;
} elseif (!isset($whm_user) || empty($whm_user) || $whm_user == 'your_whm_username') {
    $errormsg = 'You need to configure your settings for the WHM API: $whm_user is missing or not set.';
    $blocklogin = TRUE;
} elseif (!isset($whm_api_token) || empty($whm_api_token) || $whm_api_token == 'YOUR_WHM_API_TOKEN') {
    $errormsg = 'You need to configure your settings for the WHM API: $whm_api_token is missing or not set.';
    $blocklogin = TRUE;
} elseif (!isset($whm_proto) || !preg_match('/^http(s)?$/i', $whm_proto)) {
    $errormsg = "The value for \$whm_proto ('{$whm_proto}') is incorrect in your config. Please use 'http' or 'https'.";
    $blocklogin = TRUE;
} elseif (!isset($whm_sslverify)) { // Should be true or false
    $errormsg = "The value for \$whm_sslverify is not set in your config. Please set it to true or false.";
    $blocklogin = TRUE;
} else {
    $whm_sslverify = (bool) $whm_sslverify; // Ensure it's a boolean
}


// Database configuration check (for SQLite)
// $db_type and $db_file are expected from config.inc.php
if (!isset($db_type) || $db_type !== 'sqlite') {
    $errormsg = "Currently, only 'sqlite' is supported for \$db_type in your config.";
    $blocklogin = TRUE;
} elseif ($db_type === 'sqlite' && (!isset($db_file) || empty($db_file))) {
    $errormsg = "The SQLite database file path (\$db_file) is not configured in your config.";
    $blocklogin = TRUE;
}


// Default logo (can remain as is)
if (!isset($logo) || empty($logo)) {
    $logo = 'https://www.tuxis.nl/uploads/images/nsedit.png'; // Default or your preferred logo
}


/* PHP Extension Checks */
if (function_exists('curl_init') === FALSE) {
    $errormsg = "PHP cURL extension is required but not enabled. NSEdit cannot function.";
    $blocklogin = TRUE;
}
if (class_exists('SQLite3') === FALSE && $db_type === 'sqlite') {
    $errormsg = "PHP SQLite3 extension is required for database operations but not enabled.";
    $blocklogin = TRUE;
}
if (function_exists('openssl_random_pseudo_bytes') === FALSE) {
    $errormsg = "PHP OpenSSL extension (for openssl_random_pseudo_bytes) is required for security features.";
    $blocklogin = TRUE;
}
if (function_exists('json_encode') === FALSE || function_exists('json_decode') === FALSE) {
    $errormsg = "PHP JSON extension is required but not enabled.";
    $blocklogin = TRUE;
}


// Initialize SQLite database and default admin user if it doesn't exist
// This part remains largely the same, as it's for local app data.
// $default_user and $default_pass are from config.inc.php
try {
    if ($db_type === 'sqlite' && isset($db_file) && !file_exists($db_file) && class_exists('SQLite3') && !$blocklogin) {
        $db_dir = dirname($db_file);
        if (!is_dir($db_dir)) {
            if (!mkdir($db_dir, 0755, true)) {
                 $errormsg = "Failed to create database directory: {$db_dir}. Please check permissions.";
                 $blocklogin = TRUE;
            }
        }
        if (!$blocklogin && is_writable($db_dir)) {
            $db = new SQLite3($db_file, SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
            $schema_file = __DIR__ . '/scheme.sql'; // Assumes scheme.sql is in the same 'includes' directory
            if (file_exists($schema_file)) {
                $createsql = file_get_contents($schema_file);
                if ($createsql === false || !$db->exec($createsql)) {
                    $errormsg = "Failed to initialize database schema from {$schema_file}. Error: " . $db->lastErrorMsg();
                    $blocklogin = TRUE;
                    unlink($db_file); // Remove partially created DB
                } else {
                    // Create default admin user
                    $salt = bin2hex(openssl_random_pseudo_bytes(16));
                    // Use $default_user and $default_pass from config.inc.php
                    $admin_user = isset($default_user) ? $default_user : "admin";
                    $admin_pass = isset($default_pass) ? $default_pass : "admin";
                    
                    $stmt = $db->prepare("INSERT INTO users (emailaddress, password, isadmin, cpanel_username) VALUES (:email, :pass, 1, :cpuser)");
                    $stmt->bindValue(':email', $admin_user, SQLITE3_TEXT);
                    $stmt->bindValue(':pass', crypt($admin_pass, '$6$' . $salt), SQLITE3_TEXT);
                    $stmt->bindValue(':cpuser', $admin_user, SQLITE3_TEXT); // Assuming default admin might also be a cPanel user
                    
                    if (!$stmt->execute()) {
                         $errormsg = "Failed to create default admin user. Error: " . $db->lastErrorMsg();
                         $blocklogin = TRUE;
                    }
                }
            } else {
                $errormsg = "Database schema file (includes/scheme.sql) not found.";
                $blocklogin = TRUE;
            }
            if (isset($db)) $db->close(); unset($db); // Close connection after setup
        } elseif(!$blocklogin) {
             $errormsg = "Database directory {$db_dir} is not writable.";
             $blocklogin = TRUE;
        }
    }
} catch (Exception $e) {
    $errormsg = "Database setup error: " . $e->getMessage();
    $blocklogin = TRUE;
}


// Utility functions (mostly unchanged)
function string_starts_with($string, $prefix) {
    return (strncmp($string, $prefix, strlen($prefix)) === 0);
}

function string_ends_with($string, $suffix) {
    $length = strlen($suffix);
    if ($length == 0) {
        return true;
    }
    return (substr_compare($string, $suffix, -$length) === 0);
}

$_db_instance = null; // Static variable to hold DB instance

function get_db() {
    global $db_type, $db_file, $_db_instance;

    if ($_db_instance === null) {
        if ($db_type === 'sqlite' && !empty($db_file)) {
            try {
                $_db_instance = new SQLite3($db_file, SQLITE3_OPEN_READWRITE);
                $_db_instance->exec('PRAGMA foreign_keys = ON;');
            } catch (Exception $e) {
                // This is a critical failure if DB can't be opened after setup
                error_log("FATAL: Could not open SQLite database {$db_file}: " . $e->getMessage());
                // In a web context, you might want to die gracefully or show an error page.
                // For now, returning null, subsequent DB operations will fail.
                return null;
            }
        } else {
            // Handle other DB types or error if not configured
            error_log("FATAL: Database not configured or unsupported type: {$db_type}");
            return null;
        }
    }
    return $_db_instance;
}

function get_all_users() {
    $db = get_db();
    if (!$db) return array();
    $r = $db->query("SELECT id, emailaddress, cpanel_username, isadmin FROM users ORDER BY emailaddress");
    $ret = array();
    if ($r) {
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            array_push($ret, $row);
        }
    }
    return $ret;
}

function get_user_info($username_or_email) {
    $db = get_db();
    if (!$db) return false;
    // Check against both emailaddress (primary login) and cpanel_username
    $q = $db->prepare('SELECT * FROM users WHERE emailaddress = :ident OR cpanel_username = :ident LIMIT 1');
    $q->bindValue(':ident', $username_or_email, SQLITE3_TEXT);
    $result = $q->execute();
    return $result ? $result->fetchArray(SQLITE3_ASSOC) : false;
}

function user_exists($username_or_email) {
    return (bool) get_user_info($username_or_email);
}

function do_db_auth($username_or_email, $password) {
    $userinfo = get_user_info($username_or_email);

    if ($userinfo && isset($userinfo['password']) && $userinfo['password']) {
        if (crypt($password, $userinfo['password']) === $userinfo['password']) {
            return TRUE;
        }
    }
    return FALSE;
}

// $cpanel_username is optional, if provided, it links the internal user to a WHM/cPanel account
function add_user($emailaddress, $isadmin = FALSE, $password = '', $cpanel_username = null) {
    if (empty($password)) {
        $password = bin2hex(openssl_random_pseudo_bytes(16)); // Generate a strong random password
    }
    if (!preg_match('/^\$6\$/', $password)) { // Check if already a SHA-512 crypt hash
        $salt = bin2hex(openssl_random_pseudo_bytes(16));
        $password = crypt($password, '$6$' . $salt);
    }

    $db = get_db();
    if (!$db) return false;

    $q = $db->prepare('INSERT INTO users (emailaddress, password, isadmin, cpanel_username) VALUES (:email, :pass, :isadmin, :cpuser)');
    $q->bindValue(':email', $emailaddress, SQLITE3_TEXT);
    $q->bindValue(':pass', $password, SQLITE3_TEXT);
    $q->bindValue(':isadmin', (int)(bool)$isadmin, SQLITE3_INTEGER);
    $q->bindValue(':cpuser', $cpanel_username, SQLITE3_TEXT); // Can be NULL
    
    $ret = $q->execute();

    if ($ret) {
        writelog("Added user {$emailaddress}" . ($cpanel_username ? " (cPanel: {$cpanel_username})" : "") . ($isadmin ? " as admin." : "."));
    } else {
        writelog("Failed to add user {$emailaddress}. DB Error: " . $db->lastErrorMsg());
    }
    return $ret;
}

function update_user($id, $isadmin, $password, $cpanel_username = null) {
    $db = get_db();
    if (!$db) return false;

    $userinfo = $db->querySingle("SELECT emailaddress, cpanel_username FROM users WHERE id = " . (int)$id, true);
    if (!$userinfo) return false;
    $current_email = $userinfo['emailaddress'];
    $current_cpanel_user = $userinfo['cpanel_username'];

    $update_fields = ['isadmin = :isadmin'];
    $bind_params = [':isadmin' => (int)(bool)$isadmin, ':id' => (int)$id];

    if (!empty($password)) {
        if (!preg_match('/^\$6\$/', $password)) {
            $salt = bin2hex(openssl_random_pseudo_bytes(16));
            $password = crypt($password, '$6$' . $salt);
        }
        $update_fields[] = 'password = :password';
        $bind_params[':password'] = $password;
    }
    
    // Only update cpanel_username if it's provided and different, or if explicitly clearing it
    if ($cpanel_username !== null) { // Allow passing empty string to clear, or new username
        if ($cpanel_username !== $current_cpanel_user) {
            $update_fields[] = 'cpanel_username = :cpuser';
            $bind_params[':cpuser'] = empty($cpanel_username) ? null : $cpanel_username;
        }
    }

    $sql = 'UPDATE users SET ' . implode(', ', $update_fields) . ' WHERE id = :id';
    $q = $db->prepare($sql);
    foreach ($bind_params as $key => $value) {
        $q->bindValue($key, $value, is_int($value) ? SQLITE3_INTEGER : SQLITE3_TEXT);
    }
    
    $ret = $q->execute();
    writelog("Updated user {$current_email}. Admin: " . ((int)(bool)$isadmin) . 
             (!empty($password) ? ", Password changed." : "") .
             ($cpanel_username !== null && $cpanel_username !== $current_cpanel_user ? ", cPanel User set to: " . ($bind_params[':cpuser'] ?? 'NONE') : "") );
    return $ret;
}

function delete_user($id) {
    $db = get_db();
    if (!$db) return false;

    $q_select = $db->prepare('SELECT emailaddress FROM users WHERE id = ?');
    $q_select->bindValue(1, (int)$id, SQLITE3_INTEGER);
    $result = $q_select->execute();
    $userinfo = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;
    
    if ($userinfo) {
        $q_delete = $db->prepare('DELETE FROM users WHERE id = ?');
        $q_delete->bindValue(1, (int)$id, SQLITE3_INTEGER);
        $ret = $q_delete->execute();
        if ($ret) {
            writelog("Deleted user " . $userinfo['emailaddress'] . ".");
        } else {
            writelog("Failed to delete user ID {$id}. DB Error: " . $db->lastErrorMsg());
        }
        return $ret;
    }
    return false;
}

function valid_user($name) {
    // Allow email-like usernames, or simple cPanel usernames
    return (bool) preg_match("/^[a-z0-9@_.-]+$/i", $name);
}

function jtable_respond($records, $method = 'multiple', $msg = 'An unspecified error occurred.') {
    $jTableResult = array();
    if ($method == 'error') {
        $jTableResult['Result'] = "ERROR";
        $jTableResult['Message'] = $msg;
    } elseif ($method == 'single') {
        $jTableResult['Result'] = "OK";
        $jTableResult['Record'] = $records;
    } elseif ($method == 'delete') {
        $jTableResult['Result'] = "OK";
    } elseif ($method == 'options') {
        $jTableResult['Result'] = "OK";
        $jTableResult['Options'] = $records;
    } elseif ($method == 'raw') { // Added for raw text responses like zone export
        header('Content-Type: text/plain; charset=utf-8');
        echo $records; // $records is the raw string data
        // No further JSON encoding. Close DB if open.
        global $_db_instance;
        if ($_db_instance) {
            $_db_instance->close();
            $_db_instance = null;
        }
        exit(0);
    } else { // 'multiple'
        if (isset($_GET['jtPageSize']) && isset($_GET['jtStartIndex']) && is_array($records)) {
            $jTableResult['TotalRecordCount'] = count($records);
            $records = array_slice($records, (int)$_GET['jtStartIndex'], (int)$_GET['jtPageSize']);
        }
        $jTableResult['Result'] = "OK";
        $jTableResult['Records'] = $records;
    }

    global $_db_instance;
    if ($_db_instance) {
        $_db_instance->close();
        $_db_instance = null;
    }
    
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
    }
    print json_encode($jTableResult);
    exit(0);
}


// Template functions (largely unchanged, but ensure template content is WHM compatible)
function user_template_list() {
    global $templates; // From config.inc.php
    $all_templates = isset($templates) && is_array($templates) ? $templates : [];

    // Load templates from templates.d directory
    $templates_dir = __DIR__ . '/../templates.d'; // Assuming templates.d is in the root
    if (is_dir($templates_dir)) {
        if ($templdir = opendir($templates_dir)) {
            while (($entry = readdir($templdir)) !== false) {
                if (!string_ends_with($entry, ".json")) {
                    continue;
                }
                $f_path = $templates_dir . '/' . $entry;
                $f_content = file_get_contents($f_path);
                if ($f_content === false) {
                    error_log("Error reading template file: " . $f_path);
                    continue;
                }
                $t = json_decode($f_content, true);
                if ($t === null) {
                    error_log("Error decoding JSON from template file: " . $f_path . " - " . json_last_error_msg());
                    continue;
                }
                // Allow template to be an array of templates or a single template object
                if (isset($t['name']) && isset($t['records'])) { // Single template structure
                    $all_templates[] = $t;
                } elseif (is_array($t) && isset($t[0]['name'])) { // Array of templates
                    $all_templates = array_merge($all_templates, $t);
                }
            }
            closedir($templdir);
        }
    }

    $templatelist = array();
    foreach ($all_templates as $template) {
        if (is_adminuser() ||
            (isset($template['owner']) && ($template['owner'] === get_sess_user() || $template['owner'] === 'public')) ||
            (!isset($template['owner'])) // Templates without an owner are considered public
           ) {
            array_push($templatelist, $template);
        }
    }
    return $templatelist;
}

function user_template_names() {
    $templatenames = array('None' => 'None'); // Default "None" option
    foreach (user_template_list() as $template) {
        if (isset($template['name'])) {
            $templatenames[$template['name']] = $template['name'];
        }
    }
    return $templatenames;
}

// Logging functions (largely unchanged)
function writelog($line, $user = false) {
    global $logfile, $loglevel; // from config.inc.php

    if ($loglevel < 1) { // 0 = No logging, 1 = Actions, 2 = Debug
        return;
    }

    if ($user === false) {
        $user = get_sess_user(); // From session.inc.php
        if (empty($user)) {
            $user = 'SYSTEM'; // Or 'ANONYMOUS' if no session user
        }
    }

    $timestamp = date("Y-m-d H:i:s T");
    $log_entry = "[{$timestamp}] [User: {$user}] {$line}\n";

    // Using PHP's error_log for simplicity if $logfile is set, otherwise to default PHP error log
    if (!empty($logfile)) {
        error_log($log_entry, 3, $logfile);
    } else {
        error_log($log_entry); // To default PHP error log
    }
}

// The following logging functions interact with a 'logs' table in SQLite.
// If you want to keep this DB logging, ensure $logging is true and table exists.
// $logging variable was not in the original config, so it's assumed to be
// controlled by $loglevel > 0 for basic file logging.
// For DB logging, you'd need a separate $enable_db_logging = true; in config.

function getlogs_from_db() {
    // global $enable_db_logging; if ($enable_db_logging !== TRUE) return array();
    $db = get_db();
    if (!$db) return array();
    $r = $db->query('SELECT id, user, log, timestamp FROM logs ORDER BY timestamp DESC');
    $ret = array();
    if ($r) {
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            array_push($ret, $row);
        }
    }
    return $ret;
}

function clearlogs_in_db() {
    // global $enable_db_logging; if ($enable_db_logging !== TRUE) return;
    $db = get_db();
    if (!$db) return;
    $db->exec('DELETE FROM logs;');
    writelog("Log table (SQLite) truncated by user: " . get_sess_user());
}

// hash_pbkdf2 polyfill (can remain as is)
if (!function_exists('hash_pbkdf2')) {
    function hash_pbkdf2($algo, $password, $salt, $iterations, $length = 0, $rawOutput = false) {
        if (!in_array(strtolower($algo), hash_algos())) {
            trigger_error(sprintf('%s(): Unknown hashing algorithm: %s', __FUNCTION__, $algo), E_USER_WARNING);
            return false;
        }
        foreach (array(4 => $iterations, 5 => $length) as $index => $value) {
            if (!is_numeric($value)) {
                trigger_error(sprintf('%s() expects parameter %d to be long, %s given', __FUNCTION__, $index, gettype($value)), E_USER_WARNING);
                return null;
            }
        }
        $iterations = (int)$iterations;
        if ($iterations <= 0) {
            trigger_error(sprintf('%s(): Iterations must be a positive integer: %d', __FUNCTION__, $iterations), E_USER_WARNING);
            return false;
        }
        $length = (int)$length;
        if ($length < 0) {
            trigger_error(sprintf('%s(): Length must be greater than or equal to 0: %d', __FUNCTION__, $length), E_USER_WARNING);
            return false;
        }
        if (strlen($salt) > PHP_INT_MAX - 4) {
            trigger_error(sprintf('%s(): Supplied salt is too long, max of INT_MAX - 4 bytes: %d supplied', __FUNCTION__, strlen($salt)), E_USER_WARNING);
            return false;
        }
        $derivedKey = '';
        $loops = 1;
        if ($length > 0) {
            $loops = (int)ceil($length / strlen(hash($algo, '', $rawOutput)));
        }
        for ($i = 1; $i <= $loops; $i++) {
            $digest = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $block = $digest;
            for ($j = 1; $j < $iterations; $j++) {
                $digest = hash_hmac($algo, $digest, $password, true);
                $block ^= $digest;
            }
            $derivedKey .= $block;
        }
        if (!$rawOutput) {
            $derivedKey = bin2hex($derivedKey);
        }
        if ($length > 0) {
            return substr($derivedKey, 0, $length);
        }
        return $derivedKey;
    }
}

?> 
