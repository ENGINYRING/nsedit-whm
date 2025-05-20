<?php

// Ensure all necessary files are included.
// The exact paths might need adjustment based on your final directory structure.
$baseDir = __DIR__; // Assumes users.php is in the root or a known directory.

if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
    include_once($baseDir . '/includes/session.inc.php');
    include_once($baseDir . '/includes/misc.inc.php');
} elseif (file_exists($baseDir . '/../includes/config.inc.php')) { // If users.php is in a subdirectory
    include_once($baseDir . '/../includes/config.inc.php');
    include_once($baseDir . '/../includes/session.inc.php');
    include_once($baseDir . '/../includes/misc.inc.php');
} else {
    // Fallback if structure is different, though this should ideally be robust
    if (file_exists('includes/config.inc.php')) {
        include_once('includes/config.inc.php');
        include_once('includes/session.inc.php');
        include_once('includes/misc.inc.php');
    } else {
        die("Error: Could not locate essential include files from users.php. Please check paths.");
    }
}


if (!is_csrf_safe()) {
    header('HTTP/1.1 403 Forbidden');
    jtable_respond(null, 'error', "CSRF token validation failed. Please refresh the page and try again.");
    exit;
}

if (!is_adminuser()) {
    header('HTTP/1.1 403 Forbidden');
    jtable_respond(null, 'error', "You need admin privileges to access user management.");
    exit;
}

if (!isset($_GET['action'])) {
    header('HTTP/1.1 400 Bad Request');
    jtable_respond(null, 'error', 'No action specified.');
    exit;
}

$action = $_GET['action'];

try {
    switch ($action) {

        case "list":
            $users = get_all_users(); // This function was updated in misc.inc.php to include cpanel_username
            // Ensure all expected fields for jTable are present, even if null
            $output_users = array_map(function($user) {
                return [
                    'id' => $user['id'],
                    'emailaddress' => $user['emailaddress'],
                    'cpanel_username' => $user['cpanel_username'] ?? null, // Ensure it exists
                    'isadmin' => $user['isadmin'] ? 'Yes' : 'No', // Or 1/0 depending on jTable field type
                ];
            }, $users);
            jtable_respond($output_users);
            break;

        case "listoptions": // For dropdowns, typically only needs DisplayText and Value
            $users = get_all_users();
            $retusers = array();
            foreach ($users as $user) {
                // Display email, value could be email or ID depending on what's expected
                $retusers[] = array(
                    'DisplayText' => $user['emailaddress'] . (!empty($user['cpanel_username']) ? ' (cPanel: ' . $user['cpanel_username'] . ')' : ''),
                    'Value'       => $user['emailaddress'] // Or $user['id'] or $user['cpanel_username']
                );
            }
            jtable_respond($retusers, 'options');
            break;

        case "create":
            $emailaddress = isset($_POST['emailaddress']) ? trim($_POST['emailaddress']) : '';
            $isadmin = (isset($_POST['isadmin']) && ($_POST['isadmin'] === '1' || $_POST['isadmin'] === 'Yes' || $_POST['isadmin'] === true)) ? 1 : 0;
            $password = isset($_POST['password']) ? $_POST['password'] : '';
            $cpanel_username = isset($_POST['cpanel_username']) ? trim($_POST['cpanel_username']) : null;
            if (empty($cpanel_username)) $cpanel_username = null; // Ensure empty strings become null

            if (!valid_user($emailaddress)) { // valid_user checks format
                jtable_respond(null, 'error', "Invalid email address format. Please use valid characters (a-z, 0-9, @, _, ., -).");
                exit;
            }
            if ($cpanel_username !== null && !valid_user($cpanel_username)) { // cPanel username usually has stricter rules
                 jtable_respond(null, 'error', "Invalid cPanel username format. Please use valid characters (a-z, 0-9, _, -).");
                 exit;
            }

            if (empty($password)) {
                jtable_respond(null, 'error', 'Cannot create user without a password.');
                exit;
            }
            if (strlen($password) < 8) { // Example: Enforce minimum password length
                jtable_respond(null, 'error', 'Password must be at least 8 characters long.');
                exit;
            }

            if (user_exists($emailaddress)) {
                jtable_respond(null, 'error', "User with email '{$emailaddress}' already exists.");
                exit;
            }
            if ($cpanel_username && user_exists($cpanel_username)) {
                 // Check if another user already has this cPanel username mapped
                 $existing_user_with_cp_user = get_user_info($cpanel_username);
                 if ($existing_user_with_cp_user && $existing_user_with_cp_user['emailaddress'] !== $emailaddress) {
                    jtable_respond(null, 'error', "cPanel username '{$cpanel_username}' is already associated with another user.");
                    exit;
                 }
            }
            
            // add_user function in misc.inc.php now accepts cpanel_username
            if (add_user($emailaddress, $isadmin, $password, $cpanel_username)) {
                $newUser = get_user_info($emailaddress); // Fetch the newly created user to get ID
                $result = [
                    'id' => $newUser['id'],
                    'emailaddress' => $newUser['emailaddress'],
                    'cpanel_username' => $newUser['cpanel_username'] ?? null,
                    'isadmin' => $newUser['isadmin'] ? 'Yes' : 'No'
                ];
                jtable_respond($result, 'single');
            } else {
                jtable_respond(null, 'error', 'Could not create user. Please check logs.');
            }
            break;

        case "update":
            $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
            // emailaddress is usually not updatable as it's often a primary key/login
            // If it IS updatable, ensure it doesn't conflict with existing users.
            // For this example, assuming emailaddress is NOT changed here.
            $isadmin = (isset($_POST['isadmin']) && ($_POST['isadmin'] === '1' || $_POST['isadmin'] === 'Yes' || $_POST['isadmin'] === true)) ? 1 : 0;
            $password = isset($_POST['password']) ? $_POST['password'] : ''; // Empty means don't change
            $cpanel_username = isset($_POST['cpanel_username']) ? trim($_POST['cpanel_username']) : null;
             if (empty($cpanel_username)) $cpanel_username = null;


            if ($id <= 0) {
                jtable_respond(null, 'error', 'Invalid user ID for update.');
                exit;
            }
            if ($cpanel_username !== null && !valid_user($cpanel_username)) {
                 jtable_respond(null, 'error', "Invalid cPanel username format.");
                 exit;
            }
             if (!empty($password) && strlen($password) < 8) {
                jtable_respond(null, 'error', 'New password must be at least 8 characters long if provided.');
                exit;
            }

            // Check for cPanel username conflict if it's being set or changed
            if ($cpanel_username !== null) {
                $userInfo = get_user_info($id); // Get current user by ID to check their current cpanel_username
                if ($userInfo && $userInfo['cpanel_username'] !== $cpanel_username) { // If cpanel_username is changing
                    $existing_user_with_cp_user = get_user_info($cpanel_username);
                    if ($existing_user_with_cp_user && (int)$existing_user_with_cp_user['id'] !== $id) {
                        jtable_respond(null, 'error', "cPanel username '{$cpanel_username}' is already associated with another user.");
                        exit;
                    }
                }
            }


            // update_user function in misc.inc.php now accepts cpanel_username
            if (update_user($id, $isadmin, $password, $cpanel_username)) {
                $updatedUser = get_user_info($id); // Fetch by ID to get all fields
                 if (!$updatedUser && isset($_POST['emailaddress'])) { // Fallback if ID not found but email might be key
                    $updatedUser = get_user_info($_POST['emailaddress']);
                 }

                $result = [
                    'id' => $updatedUser['id'],
                    'emailaddress' => $updatedUser['emailaddress'],
                    'cpanel_username' => $updatedUser['cpanel_username'] ?? null,
                    'isadmin' => $updatedUser['isadmin'] ? 'Yes' : 'No'
                ];
                jtable_respond($result, 'single');
            } else {
                jtable_respond(null, 'error', 'Could not update user. Please check logs.');
            }
            break;

        case "delete":
            $id = isset($_POST['id']) ? intval($_POST['id']) : 0;

            if ($id <= 0) {
                jtable_respond(null, 'error', 'Invalid user ID for deletion.');
                exit;
            }
            
            // Prevent deleting the last admin user or self if admin (optional safety)
            $currentUserInfo = get_user_info(get_sess_user());
            if ($currentUserInfo && (int)$currentUserInfo['id'] === $id && (int)$currentUserInfo['isadmin'] === 1) {
                 $adminCountResult = get_db()->querySingle("SELECT COUNT(*) FROM users WHERE isadmin = 1");
                 if ($adminCountResult <= 1) {
                     jtable_respond(null, 'error', 'Cannot delete the last administrative user.');
                     exit;
                 }
            }


            if (delete_user($id) !== FALSE) {
                jtable_respond(null, 'delete');
            } else {
                jtable_respond(null, 'error', 'Could not delete user. Please check logs.');
            }
            break;

        default:
            jtable_respond(null, 'error', 'Invalid action: ' . htmlspecialchars($action));
            break;
    }
} catch (Exception $e) {
    writelog("Error in users.php action '{$action}': " . $e->getMessage());
    jtable_respond(null, 'error', "An unexpected error occurred: " . htmlspecialchars($e->getMessage()));
}

?> 
