<?php

// This script is intended to be run from the command line (CLI).

// Determine the base directory of the application
// This assumes rotate-logs.php is in the root directory of the application,
// alongside the 'includes' folder. Adjust if your structure is different.
$baseDir = __DIR__;

// Include necessary files
// It's crucial that config.inc.php is loaded first.
if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
} else {
    echo "Error: Configuration file (includes/config.inc.php) not found.\n";
    exit(1);
}

if (file_exists($baseDir . '/includes/misc.inc.php')) {
    include_once($baseDir . '/includes/misc.inc.php');
} else {
    echo "Error: Miscellaneous functions file (includes/misc.inc.php) not found.\n";
    exit(1);
}

// No session is started for CLI scripts, so session.inc.php might not be strictly needed
// unless some functions in misc.inc.php indirectly rely on it (e.g. get_sess_user for writelog).
// The refactored writelog in misc.inc.php defaults to 'SYSTEM' if no session user.


if (php_sapi_name() !== 'cli') {
    header('HTTP/1.1 403 Forbidden');
    echo "<h1>403 Forbidden</h1>";
    echo "<p>This script is intended to be run from the command line interface (CLI) only.</p>";
    exit(1);
}

// Check if log rotation is enabled in the configuration
// $allowrotatelogs should be defined in config.inc.php
if (!isset($allowrotatelogs) || $allowrotatelogs !== true) {
    echo "Log rotation is disabled in the configuration (check \$allowrotatelogs in config.inc.php).\n";
    // writelog("Log rotation attempted but is disabled in config.", "SYSTEM_ROTATE_LOGS_CLI");
    exit(0); // Exit gracefully, not an error if intentionally disabled.
}

// The rotatelogs() function is now expected to be in misc.inc.php
// and should handle its own logging via writelog().
// The $current_user['username']='<system>' from the original script is not directly
// used by the refactored writelog, which defaults to 'SYSTEM' if no session user.

echo "Attempting to rotate logs...\n";

try {
    // The rotatelogs() function in the refactored misc.inc.php should:
    // 1. Check if DB logging and $logsdirectory are configured and valid.
    // 2. Get logs from the DB using getlogs_from_db().
    // 3. Write them to a new file in $logsdirectory.
    // 4. Clear the logs from the DB using clearlogs_in_db().
    // 5. Log its own actions using writelog().
    
    $rotatedFilename = rotatelogs(); // This function is from misc.inc.php

    if ($rotatedFilename !== false && $rotatedFilename !== null) {
        $message = "Logs successfully rotated. Archived to: " . ($logsdirectory ?? '[configured_log_directory]') . "/" . $rotatedFilename . "\n";
        echo $message;
        // writelog($message, "SYSTEM_ROTATE_LOGS_CLI"); // rotatelogs() should log its success.
    } else {
        // rotatelogs() should have already logged the specific error via writelog()
        echo "Log rotation failed. Please check application logs (e.g., {$logfile}) for details.\n";
        // No need to call writelog here if rotatelogs() does it.
        exit(1); // Exit with an error code if rotation failed
    }

} catch (Exception $e) {
    $errorMessage = "An error occurred during log rotation: " . $e->getMessage() . "\n";
    echo $errorMessage;
    // Log this critical failure
    if (function_exists('writelog')) {
        writelog("CRITICAL: Log rotation script failed: " . $e->getMessage(), "SYSTEM_ROTATE_LOGS_CLI");
    } else {
        error_log("CRITICAL: Log rotation script failed: " . $e->getMessage());
    }
    exit(1);
}

exit(0); // Success

?> 
