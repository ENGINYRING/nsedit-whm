<?php

// Ensure all necessary files are included.
$baseDir = __DIR__; // Assumes logs.php is in the root or a known directory.

if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
    include_once($baseDir . '/includes/session.inc.php');
    include_once($baseDir . '/includes/misc.inc.php');
} elseif (file_exists($baseDir . '/../includes/config.inc.php')) { // If logs.php is in a subdirectory
    include_once($baseDir . '/../includes/config.inc.php');
    include_once($baseDir . '/../includes/session.inc.php');
    include_once($baseDir . '/../includes/misc.inc.php');
} else {
    // Fallback if structure is different
    if (file_exists('includes/config.inc.php')) {
        include_once('includes/config.inc.php');
        include_once('includes/session.inc.php');
        include_once('includes/misc.inc.php');
    } else {
        // Attempt to output a JSON error if jtable_respond is not available yet
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['Result' => 'ERROR', 'Message' => 'Critical Error: Could not locate essential include files from logs.php. Please check paths.']);
        exit;
    }
}

if (!is_csrf_safe()) {
    header('HTTP/1.1 403 Forbidden');
    // Ensure jtable_respond is available or use a direct JSON response
    if (function_exists('jtable_respond')) {
        jtable_respond(null, 'error', "CSRF token validation failed. Please refresh the page and try again.");
    } else {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['Result' => 'ERROR', 'Message' => 'CSRF token validation failed.']);
    }
    exit;
}

if (!is_adminuser()) {
    header('HTTP/1.1 403 Forbidden');
    if (function_exists('jtable_respond')) {
        jtable_respond(null, 'error', "You need admin privileges to access logs.");
    } else {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['Result' => 'ERROR', 'Message' => 'Admin privileges required.']);
    }
    exit;
}

if (!isset($_GET['action'])) {
    header('HTTP/1.1 400 Bad Request');
    if (function_exists('jtable_respond')) {
        jtable_respond(null, 'error', 'No action specified.');
    } else {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['Result' => 'ERROR', 'Message' => 'No action specified.']);
    }
    exit;
}

$action = $_GET['action'];

// Check if DB logging is intended to be used.
// The original misc.inc.php had getlogs/clearlogs which implicitly used DB.
// The refactored misc.inc.php has getlogs_from_db/clearlogs_in_db.
// We'll assume this page is for DB logs. If $enable_db_logging is false, these might do nothing or error.
// A global $enable_db_logging could be checked here if defined in config.inc.php.
// For now, we proceed assuming the functions exist and will handle their own enablement.

try {
    switch ($action) {
        case "list":
            // The function getlogs_from_db() is defined in misc.inc.php (refactored version)
            // It retrieves logs from the SQLite 'logs' table.
            $logs = getlogs_from_db();
            jtable_respond($logs); // jTable expects an array of log objects/arrays
            break;

        case "clear":
            // The function clearlogs_in_db() is defined in misc.inc.php (refactored version)
            // It truncates the SQLite 'logs' table.
            clearlogs_in_db();
            // After clearing, it's good practice to confirm the action.
            // jtable_respond with 'delete' type is often used for successful deletions.
            // Or, send a custom success message.
            jtable_respond(null, 'delete', "Logs cleared successfully."); // 'delete' implies success for jTable
            break;

        default:
            jtable_respond(null, 'error', 'Invalid action: ' . htmlspecialchars($action));
            break;
    }
} catch (Exception $e) {
    // Log the actual error for server admin
    if (function_exists('writelog')) { // Use writelog if available
         writelog("Error in logs.php action '{$action}': " . $e->getMessage() . "\nTrace: " . $e->getTraceAsString());
    } else {
        error_log("Error in logs.php action '{$action}': " . $e->getMessage());
    }
    // Provide a user-friendly error message
    jtable_respond(null, 'error', "An unexpected error occurred while processing logs: " . htmlspecialchars($e->getMessage()));
}

?> 
