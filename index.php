<?php

// Ensure all necessary files are included first.
// This setup assumes index.php is in the project root.
$baseDir = __DIR__;
if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
    include_once($baseDir . '/includes/session.inc.php');
    include_once($baseDir . '/includes/misc.inc.php');
} else {
    // A basic error if config can't be found, as the page won't function.
    die("Critical Error: Main configuration file (includes/config.inc.php) not found. Please check installation.");
}

global $errormsg, $blocklogin, $title, $logo, $menutype, $allowzoneadd, $allowusermanage, $allowrotatelogs, $allowclearlogs, $default_user, $default_pass, $defaults, $templates, $auth_type, $secret; // Ensure all used globals are declared or loaded from config

// Initial checks from misc.inc.php (which should have set $blocklogin and $errormsg if issues)
if ($blocklogin === TRUE && empty($errormsg)) { // If misc.inc.php blocked but didn't set a message
    $errormsg = "Initial configuration checks failed. Please review your config.inc.php and ensure all requirements are met.";
}


// Handle logout action
if (isset($_GET['logout']) || isset($_POST['logout'])) {
    logout(); // from session.inc.php
    header("Location: index.php");
    exit(0);
}

// Handle login attempt
if (!is_logged_in() && isset($_POST['formname']) && $_POST['formname'] === "loginform") {
    if (!try_login()) { // try_login is from session.inc.php
        // $errormsg is usually set by try_login() via session_start_once() if login fails
        if (empty($errormsg)) $errormsg = "Authentication failed. Please check your username and password.";
    } else {
        // Successful login, redirect to clear POST data
        header("Location: index.php");
        exit(0);
    }
}

// Handle password change attempt
if (is_logged_in() && isset($_POST['formname']) && $_POST['formname'] === "changepwform") {
    if (get_sess_user() === $_POST['username']) { // User can only change their own password via this form
        if (!empty($_POST['password']) && $_POST['password'] === $_POST['password2']) {
            if (strlen($_POST['password']) >= 8) { // Enforce minimum password length
                // update_user is from misc.inc.php. Need to pass cpanel_username as null or existing.
                $userInfo = get_user_info(get_sess_user());
                if (!update_user(get_sess_userid(), is_adminuser(), $_POST['password'], $userInfo['cpanel_username'] ?? null )) {
                    $errormsg = "Unable to update password. Please try again or contact an administrator.";
                } else {
                    // Password changed successfully, maybe provide a success message or redirect
                    // For simplicity, we'll let the page reload. A success message could be set in session.
                }
            } else {
                $errormsg = "Password must be at least 8 characters long.";
            }
        } elseif ($_POST['password'] !== $_POST['password2']) {
            $errormsg = "Passwords do not match.";
        } else {
            $errormsg = "Password cannot be empty.";
        }
    } else {
        $errormsg = "You can only update your own password.";
    }
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title ?? 'NSEdit'); ?> WHM</title>
    <link href="jquery-ui/themes/base/all.css" rel="stylesheet" type="text/css"/>
    <link href="jtable/lib/themes/metro/<?php echo htmlspecialchars($themecolor ?? 'blue'); ?>/jtable.min.css" rel="stylesheet" type="text/css"/>
    <link href="css/base.css" rel="stylesheet" type="text/css"/>
    <?php if (isset($menutype) && $menutype === 'horizontal') { ?>
    <link href="css/horizontal-menu.css" rel="stylesheet" type="text/css"/>
    <?php } ?>

    <script src="jquery-ui/external/jquery/jquery.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/core.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/widget.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/mouse.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/draggable.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/position.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/button.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/resizable.js" type="text/javascript"></script>
    <script src="jquery-ui/ui/dialog.js" type="text/javascript"></script>
    <script src="jtable/lib/jquery.jtable.min.js" type="text/javascript"></script>
    <script src="js/addclear/addclear.js" type="text/javascript"></script>
</head>

<?php
if (!is_logged_in()) {
?>
<body onload="document.getElementById('username').focus()">
<div class="loginblock">
    <div class="logo">
        <?php if (!empty($logo)) { echo '<img src="' . htmlspecialchars($logo) . '" alt="Logo"/>'; } ?>
    </div>
    <div class="login">
        <?php if (!empty($errormsg)) {
            echo '<p class="error-message">' . nl2br(htmlspecialchars($errormsg)) . '</p>';
        }
        if ($blocklogin === TRUE) {
             echo '<p class="error-message"><strong>Login is currently blocked due to a configuration issue. Please contact the administrator.</strong></p>';
        }
        ?>
        <form action="index.php" method="post">
            <table>
                <tr>
                    <td class="label">Username:</td>
                    <td><input id="username" type="text" name="username" required></td>
                </tr>
                <tr>
                    <td class="label">Password:</td>
                    <td><input type="password" name="password" required></td>
                </tr>
                <?php
                // Autologin checkbox (if $secret is configured for token-based remember me)
                // This feature might need review for security best practices.
                if (isset($secret) && $secret) { 
                ?>
                <tr>
                    <td class="label">Remember me:</td>
                    <td><input type="checkbox" name="autologin" value="1"></td>
                </tr>
                <?php
                }
                ?>
                <tr>
                    <td></td>
                    <td><input type="submit" name="submit" value="Log In" <?php if ($blocklogin === TRUE) { echo "disabled"; }; ?>></td>
                </tr>
            </table>
            <input type="hidden" name="formname" value="loginform">
        </form>
    </div>
</div>
</body>
</html>
<?php
exit(0);
} // End of not logged in block

// If login is blocked after successful login attempt (should not happen if initial checks are good)
if ($blocklogin === TRUE) {
   echo "<h2>Configuration Error</h2>";
   echo "<p>" . nl2br(htmlspecialchars($errormsg)) . "</p>";
   echo "<p><a href=\"index.php?logout=1\">Logout and Retry</a></p>"; // Allow logout
   exit(0);
}

// Ensure CSRF_TOKEN is available for JavaScript
if (!defined('CSRF_TOKEN') && function_exists('get_csrf_token')) {
    define('CSRF_TOKEN', get_csrf_token());
} elseif (!defined('CSRF_TOKEN')) {
    define('CSRF_TOKEN', 'fallback_csrf_token_error_session_not_started'); // Should not happen
}

?>
<body>
<div id="wrap">
    <div id="dnssecinfoDialog" title="DNSSEC Information" style="display:none;">
        <div id="dnssecinfoContent"></div>
    </div>

    <div id="clearlogsDialog" title="Confirm Clear Logs" style="display: none;">
        <p>Are you sure you want to clear the current logs from the database? This action cannot be undone.</p>
        <?php if(isset($allowrotatelogs) && $allowrotatelogs) { ?>
            <p>Consider using "Rotate logs" to archive them first if needed.</p>
        <?php } ?>
    </div>
    <div id="rotatelogsDialog" title="Confirm Rotate Logs" style="display: none;">
        <p>Are you sure you want to rotate the current logs? This will archive current logs and clear the database table.</p>
    </div>

    <div id="searchzoneDialog" title="Search Zone Records" style="display: none; text-align: right;">
        <form>
        <table border="0">
        <tr><td><label for="searchzone-label">Label:</label></td><td><input type="text" id ="searchzone-label" name="searchzone-label"></td></tr>
        <tr><td><label for="searchzone-type">Type:</label></td><td style="text-align: left;"><select id="searchzone-type" name="searchzone-type">
            <option value=""></option>
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="CAA">CAA</option>
            <option value="CERT">CERT</option>
            <option value="CNAME">CNAME</option>
            <option value="DNAME">DNAME</option>
            <option value="DS">DS</option>
            <option value="LOC">LOC</option>
            <option value="MX">MX</option>
            <option value="NAPTR">NAPTR</option>
            <option value="NS">NS</option>
            <option value="PTR">PTR</option>
            <option value="SOA">SOA</option>
            <option value="SPF">SPF (as TXT)</option>
            <option value="SRV">SRV</option>
            <option value="SSHFP">SSHFP</option>
            <option value="TLSA">TLSA</option>
            <option value="TXT">TXT</option>
            <option value="SMIMEA">SMIMEA</option>
        </select></td></tr>
        <tr><td><label for="searchzone-content">Content:</label></td><td><input type="text" id ="searchzone-content" name="searchzone-content"></td></tr>
        </table>
        </form>
    </div>
    
    <?php if (is_adminuser()) { ?>
    <div id="searchlogsDialog" title="Search Logs" style="display: none; text-align: right;">
        <form>
        <table border="0">
        <tr><td><label for="searchlogs-user">User:</label></td><td><input type="text" id ="searchlogs-user" name="searchlogs-user"></td></tr>
        <tr><td><label for="searchlogs-entry">Log Entry:</label></td><td><input type="text" id ="searchlogs-entry" name="searchlogs-entry"></td></tr>
        </table>
        </form>
    </div>
    <?php } ?>


    <div id="menu" class="jtable-main-container <?php if (isset($menutype) && $menutype === 'horizontal') { echo 'horizontal'; } ?>">
        <div class="jtable-title menu-title">
            <div class="jtable-title-text">
                <?php echo htmlspecialchars($title ?? 'NSEdit'); ?> (WHM)
            </div>
        </div>
        <ul>
            <li><a href="#" id="zoneadmin">Zones</a></li>
            <?php if (is_adminuser() && $allowusermanage === TRUE) { ?>
                <li><a href="#" id="useradmin">Users</a></li>
            <?php } ?>
            <?php if (is_adminuser() && (isset($loglevel) && $loglevel > 0)) { // Show logs if logging is enabled ?>
                <li><a href="#" id="logadmin">Logs</a></li>
            <?php } ?>
            <?php if (has_local_auth()) { // Only show "About Me" if internal auth is used ?>
                 <li><a href="#" id="aboutme">My Account</a></li>
            <?php } ?>
            <li><a href="index.php?logout=1">Logout (<?php echo htmlspecialchars(get_sess_user()); ?>)</a></li>
        </ul>
    </div>
    <?php if (!empty($errormsg)) { // Display errors after menu
        echo '<div class="error-container"><p class="error-message">' . nl2br(htmlspecialchars($errormsg)) . '</p></div>';
    }
    ?>
    <div id="zones">
        <?php if ($allowzoneadd === TRUE) { ?>
        <div style="display: none;" id="ImportZoneDialog"></div> <?php } ?>
        <?php if (is_adminuser()) { ?>
        <div style="display: none;" id="CloneZoneDialog"></div>
        <?php } ?>
        <div class="tables" id="ZoneTableContainer"> <div class="searchbar" id="searchbar">
                <label for="domsearch">Search Zones: </label>
                <input type="text" id="domsearch" name="domsearch" placeholder="Enter domain name..."/>
            </div>
        </div>
        </div>

    <?php if (is_adminuser() && $allowusermanage === TRUE) { ?>
    <div id="users" style="display:none;">
        <div class="tables" id="UserTableContainer"></div>
    </div>
    <?php } ?>

    <?php if (is_adminuser() && (isset($loglevel) && $loglevel > 0)) { ?>
    <div id="logs" style="display:none;">
        <div class="tables" id="LogTableContainer"></div>
        <?php if(isset($allowrotatelogs) && $allowrotatelogs && isset($logsdirectory)) { // Check if logsdirectory is set ?>
        <br>View Archived Log:
        <select id="logfile_select">
        <option value="">(Current Database Logs)</option>
        <?php
            // listrotatedlogs() is from misc.inc.php
            $logfiles_list = function_exists('listrotatedlogs') ? listrotatedlogs() : false;
            if($logfiles_list !== FALSE && is_array($logfiles_list)) {
                foreach ($logfiles_list as $filename) {
                    echo '<option value="' . htmlspecialchars($filename) . '">' . htmlspecialchars(str_replace(".json","",$filename)) . "</option>\n";
                }
            }
        ?></select>
        <?php } else { ?>
        <input type="hidden" id="logfile_select" value="">
        <?php } ?>
    </div>
    <?php } ?>

    <?php if (has_local_auth()) { ?>
    <div id="AboutMe" style="display:none;">
        <div class="tables">
            <h3>Change My Password</h3>
            <p>Hi <?php echo htmlspecialchars(get_sess_user()); ?>. You can change your password here.</p>
            <form action="index.php" method="POST" id="passwordChangeForm">
                <table>
                    <tr>
                        <td class="label"><label for="current_username">Username:</label></td>
                        <td><input readonly value="<?php echo htmlspecialchars(get_sess_user()); ?>" id="current_username" type="text" name="username"></td>
                    </tr>
                    <tr>
                        <td class="label"><label for="changepw1">New Password:</label></td>
                        <td><input type="password" name="password" id="changepw1" required minlength="8"></td>
                    </tr>
                    <tr>
                        <td class="label"><label for="changepw2">Confirm Password:</label></td>
                        <td><input type="password" name="password2" id="changepw2" required minlength="8"></td>
                    </tr>
                    <tr>
                        <td></td>
                        <td><input type="submit" name="submit" id="changepwsubmit" value="Change Password" disabled></td>
                    </tr>
                </table>
                <input type="hidden" name="formname" value="changepwform">
                <input type="hidden" name="X-CSRF-Token" value="<?php echo CSRF_TOKEN; ?>">
            </form>
        </div>
    </div>
    <?php } ?>
</div> <script type="text/javascript">
// Ensure CSRF token is available globally for AJAX setup
window.csrf_token = '<?php echo CSRF_TOKEN; ?>';

$(document).ready(function () {
    // CSRF setup for all AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            // These HTTP methods do not require CSRF protection
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRF-Token", window.csrf_token);
            }
        }
    });

    var $epoch = Math.round(+new Date()/1000); // For cache busting options URLs if needed

    // Helper function to display DNSSEC icon and fetch details
    function displayDnssecIcon(data) { // data is the row data from jTable
        var zone = data.record;
        if (zone.dnssec === true || zone.dnssec === 'Yes') { // Check for boolean true or string "Yes"
            var $img = $('<img class="list clickme" src="img/lock.png" title="DNSSEC Enabled - Click for Details" />');
            $img.click(function () {
                $('#dnssecinfoContent').html('<p>Loading DNSSEC details...</p>');
                $("#dnssecinfoDialog").dialog({
                    modal: true,
                    title: "DNSSEC Details for " + zone.name,
                    width: 600,
                    open: function() {
                        // AJAX call to fetch keyinfo
                        // This assumes getzonekeys returns data in a format that can be displayed
                        // The WhmApi::getzonekeys is a placeholder, so this will need adjustment
                        // once that API call is fully implemented.
                        $.post('zones.php?action=getzonekeys&zoneid=' + encodeURIComponent(zone.name), { 'X-CSRF-Token': window.csrf_token })
                            .done(function(keyData) {
                                if (keyData.Result === "OK" && keyData.Records && keyData.Records.length > 0) {
                                    var content = '';
                                    $.each(keyData.Records, function (i, val) {
                                        content += "<p><strong>Key Type: " + (val.keytype || 'N/A') + " (ID: " + (val.id || 'N/A') + ")</strong><br/>Active: " + (val.active ? 'Yes' : 'No') + "</p>";
                                        if (val.dstxt) {
                                            content += "<pre style='white-space: pre-wrap; word-wrap: break-word;'>" + $('<div/>').text(val.dstxt).html() + "</pre>";
                                        } else if (val.dnskey) {
                                             content += "<pre style='white-space: pre-wrap; word-wrap: break-word;'>DNSKEY: " + $('<div/>').text(val.dnskey).html() + "</pre>";
                                        }
                                    });
                                    $('#dnssecinfoContent').html(content);
                                } else if (keyData.Result === "OK") {
                                     $('#dnssecinfoContent').html('<p>No detailed DNSSEC key information available or DNSSEC might not be fully configured with keys.</p>');
                                } else {
                                    $('#dnssecinfoContent').html('<p>Error loading DNSSEC details: ' + (keyData.Message || 'Unknown error') + '</p>');
                                }
                            })
                            .fail(function() {
                                $('#dnssecinfoContent').html('<p>Failed to retrieve DNSSEC details.</p>');
                            });
                    },
                    buttons: { "Close": function() { $(this).dialog("close"); } }
                });
            });
            return $img;
        } else {
            return '<img class="list" src="img/lock_open.png" title="DNSSEC Disabled" />';
        }
    }

    // Helper function to display Export icon
    function displayExportIcon(data) { // data is the row data from jTable
        var zone = data.record;
        var $img = $('<img class="list clickme" src="img/export.png" title="Export zone ' + zone.name + '" />');
        $img.click(function () {
            // Using $.get and manually creating blob for download
            $.ajax({
                url: 'zones.php?action=export&zoneid=' + encodeURIComponent(zone.name),
                type: 'GET',
                beforeSend: function(xhr){ // Manually add CSRF for GET if needed, though typically not.
                    // xhr.setRequestHeader("X-CSRF-Token", window.csrf_token);
                },
                success: function(zoneFileContent) {
                    var blob = new Blob([zoneFileContent], { type: 'text/plain;charset=utf-8' });
                    var dl = document.createElement('a');
                    dl.href = URL.createObjectURL(blob);
                    dl.download = zone.name + '.txt';
                    document.body.appendChild(dl); // Required for Firefox
                    dl.click();
                    document.body.removeChild(dl);
                    URL.revokeObjectURL(dl.href);
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    alert("Error exporting zone: " + textStatus + " - " + errorThrown);
                }
            });
        });
        return $img;
    }

    // Helper function to display content, handling potential HTML and zone name highlighting
    function displayContent(fieldName, baseZoneName) {
        return function(data) {
            var text = data.record[fieldName];
            if (typeof text === 'boolean') {
                text = text ? 'Yes' : 'No';
            } else if (text === null || typeof text === 'undefined') {
                text = '';
            } else {
                text = String(text); // Ensure it's a string
            }

            var $span = $('<span></span>');
            if (fieldName === 'name' && baseZoneName) {
                var cleanBaseZone = baseZoneName.replace(/\.$/, ''); // Remove trailing dot for comparison
                var cleanRecordName = text.replace(/\.$/, '');

                if (cleanRecordName === cleanBaseZone || cleanRecordName === '@.' + cleanBaseZone || cleanRecordName === '@') {
                    $span.text('@').attr('title', text); // Display '@' for apex
                } else if (cleanRecordName.endsWith('.' + cleanBaseZone)) {
                    var label = cleanRecordName.substring(0, cleanRecordName.length - (cleanBaseZone.length + 1));
                    $span.text(label);
                } else {
                    $span.text(text); // Absolute name or different zone
                }
            } else {
                 // For general content, escape HTML to prevent XSS if content might be user-generated HTML
                 // However, for DNS records, content is usually plain text.
                 // If content could be maliciously crafted HTML and displayed raw, this is a risk.
                 // For now, assuming DNS content is mostly safe, but consider .text() for safety.
                 // $span.text(text); // Safer if content is purely textual
                 $span.html(text.replace(/\n/g, '<br/>')); // Allow line breaks in TXT records
            }
            return $span;
        };
    }
    
    // Zone Management Table (Master Zones)
    $('#ZoneTableContainer').jtable({
        title: 'DNS Zones',
        paging: true,
        pageSize: 20,
        sorting: true, // Enable sorting
        defaultSorting: 'name ASC',
        messages: {
            addNewRecord: 'Add New Zone',
            editRecord: 'Edit Zone Settings',
            noDataAvailable: 'No zones found. Use "Add New Zone" to create one.',
            deleteConfirmation: 'This zone and all its records will be PERMANENTLY DELETED. Are you sure?'
        },
        toolbar: {
            hoverAnimation: true,
            items: [
                <?php if ($allowzoneadd === TRUE) { ?>
                {
                    icon: 'jtable/lib/themes/metro/add.png', // Standard add icon
                    text: 'Add New Zone',
                    click: function() {
                        $('#ZoneTableContainer').jtable('showCreateForm');
                    }
                },
                // Import Zone functionality might be complex due to parsing zone file text.
                // For now, focusing on direct creation.
                // {
                //     icon: 'img/import.png', // Custom import icon
                //     text: 'Import Zone from Text',
                //     click: function() { /* Logic for import dialog */ }
                // },
                <?php } ?>
                <?php if (is_adminuser()) { ?>
                {
                    icon: 'img/clone.png', // Custom clone icon
                    text: 'Clone Zone',
                    click: function() {
                         $('#CloneZoneDialog').jtable('showCreateForm');
                    }
                }
                <?php } ?>
            ]
        },
        actions: {
            listAction:   'zones.php?action=list',
            // Create and Update actions for zones will manage zone properties, not individual records here.
            // Record management is done in the child table.
            <?php if ($allowzoneadd === TRUE) { ?>
            createAction: 'zones.php?action=create',
            <?php } ?>
            <?php if (is_adminuser()) { ?> // Only admins can typically change account/ownership
            updateAction: 'zones.php?action=update',
            deleteAction: 'zones.php?action=delete'
            <?php } elseif ($allowzoneadd === TRUE) { // Non-admins can delete zones they own if allowed to create
                 // This assumes check_account in zones.php correctly verifies ownership for delete
                 ?>
                 deleteAction: 'zones.php?action=delete',
            <?php }?>
        },
        fields: {
            id: { // This will be the domain name
                key: true,
                list: false, // Not usually displayed in the main list, but used as key
                create: false,
                edit: false
            },
            name: {
                title: 'Domain Name',
                width: '30%',
                display: displayContent('name'),
                edit: false, // Domain name typically not editable after creation this way
                input: function(data) { // For create form
                    if (data.formType === 'create') {
                        return '<input type="text" name="name" required pattern="^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$" title="Enter a valid domain name, e.g., example.com">';
                    } else { // For edit form, display as readonly
                        return '<span>' + data.record.name + '</span><input type="hidden" name="name" value="' + data.record.name + '"/>';
                    }
                }
            },
            // 'kind' field is removed as WHM zones are generally 'Master' in this context
            <?php if (is_adminuser()) { ?>
            account: { // cPanel username
                title: 'cPanel Account',
                width: '15%',
                display: displayContent('account'),
                options: 'users.php?action=listoptions&e=' + $epoch, // Fetch user list for dropdown
                 // For create, admin sets it. For edit, admin can change it.
                input: function(data) {
                    var currentVal = data.value || (data.record ? data.record.account : '');
                    if (data.formType === 'create') {
                         return '<input type="text" name="account" value="' + (currentVal || '<?php echo htmlspecialchars(get_sess_user()); ?>') + '" title="cPanel username that owns this zone">';
                    } else { // Edit form
                         return '<input type="text" name="account" value="' + currentVal + '" title="cPanel username that owns this zone">';
                    }
                }
            },
            <?php } else { ?>
             account: { // For non-admins, display only
                title: 'cPanel Account',
                width: '15%',
                display: displayContent('account'),
                create: false,
                edit: false
            },
            <?php } ?>
            primary_ip: { // New field for WHM 'adddns'
                title: 'Primary IP (for new zone)',
                list: false, // Not shown in list, only for creation form
                create: true,
                edit: false, // Not editable after zone creation via this field
                input: function(data) {
                    return '<input type="text" name="primary_ip" pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" title="Enter the primary IPv4 address for this zone." required>';
                }
            },
            serial: {
                title: 'SOA Serial',
                width: '15%',
                display: displayContent('serial'),
                create: false,
                edit: false
            },
            dnssec: { // Placeholder for DNSSEC status display
                title: 'DNSSEC',
                width: '10%',
                create: false,
                edit: false,
                display: displayDnssecIcon // Assumes 'dnssec' boolean and 'keyinfo' array in record
            },
            actions: {
                title: 'Actions',
                width: '10%',
                sorting: false,
                edit: false,
                create: false,
                display: function(data) {
                    var zone = data.record;
                    var $container = $('<span></span>');
                    
                    // Edit Records Button
                    var $editRecordsButton = $('<button title="Edit Records"><img src="img/edit.png" alt="Edit Records" /> Records</button>');
                    $editRecordsButton.click(function () {
                        // This is where the child table for records is opened
                        $('#ZoneTableContainer').jtable('openChildTable',
                            $(this).closest('tr'), // Reference to the parent table row
                            {
                                title: 'DNS Records for ' + zone.name,
                                messages: {
                                    addNewRecord: 'Add New Record to ' + zone.name,
                                    editRecord: 'Edit DNS Record',
                                    noDataAvailable: 'No records found for ' + zone.name + '. Use "Add New Record" to create them.',
                                    deleteConfirmation: 'This DNS record will be PERMANENTLY DELETED. Are you sure?'
                                },
                                actions: {
                                    listAction:   'zones.php?action=listrecords&zoneid=' + encodeURIComponent(zone.name),
                                    createAction: 'zones.php?action=createrecord&zoneid=' + encodeURIComponent(zone.name),
                                    updateAction: 'zones.php?action=editrecord&zoneid=' + encodeURIComponent(zone.name),
                                    deleteAction: 'zones.php?action=deleterecord&zoneid=' + encodeURIComponent(zone.name)
                                },
                                fields: {
                                    // The 'id' for records is a JSON string containing Line, name, type, original content
                                    id: { key: true, type: 'hidden', list: false, create: false, edit: false },
                                    Line: { title: 'Line', list: false, edit: false, create: false }, // For reference, not displayed
                                    name: { 
                                        title: 'Name/Label', 
                                        width: '25%',
                                        input: function(editData) {
                                            var recordName = editData.value || (editData.record ? editData.record.name : '');
                                            // Make it relative to zone for display if it's a subdomain
                                            var zoneBaseName = zone.name.replace(/\.$/, '');
                                            var recordNameDisplay = recordName.replace(/\.$/, '');
                                            if (recordNameDisplay === zoneBaseName || recordNameDisplay === '@') {
                                                recordNameDisplay = '@';
                                            } else if (recordNameDisplay.endsWith('.' + zoneBaseName)) {
                                                recordNameDisplay = recordNameDisplay.substring(0, recordNameDisplay.length - (zoneBaseName.length + 1));
                                            }
                                            return '<input type="text" name="name" value="' + htmlspecialchars(recordNameDisplay) + '" title="Enter record name (e.g., @, www, mail) or FQDN.">';
                                        },
                                        display: displayContent('name', zone.name)
                                    },
                                    type: { 
                                        title: 'Type', 
                                        width: '10%',
                                        options: { /* Filled by getRecordTypeOptions */ }
                                    },
                                    content: { 
                                        title: 'Content/Value', 
                                        width: '40%',
                                        input: function(editData) {
                                            // For MX, content is "priority host". For SRV, "priority weight port target"
                                            // For TXT, might be long.
                                            var currentContent = editData.value || (editData.record ? editData.record.content : '');
                                            if (editData.formType === 'edit' && editData.record && (editData.record.type === 'MX' || editData.record.type === 'SRV')) {
                                                 // If content was an array in the record, join it for display in simple text input
                                                 if (Array.isArray(currentContent)) currentContent = currentContent.join(' ');
                                            }
                                            if (editData.record && editData.record.type === 'TXT') {
                                                return '<textarea name="content" style="width:95%;" rows="3">' + htmlspecialchars(currentContent) + '</textarea>';
                                            }
                                            return '<input type="text" name="content" value="' + htmlspecialchars(currentContent) + '" style="width:95%;">';
                                        }
                                    },
                                    ttl: { title: 'TTL', width: '10%', defaultValue: '<?php echo $defaults['ttl'] ?? 14400; ?>' },
                                    // 'disabled' and 'setptr' are removed for WHM
                                },
                                // Dynamically set record type options based on whether it's a reverse zone
                                formCreated: function (event, data) {
                                    // Add CSRF token to child table forms
                                    data.form.append('<input type="hidden" name="X-CSRF-Token" value="' + window.csrf_token + '" />');
                                    
                                    var recordTypes = {
                                        'A': 'A (Address)', 'AAAA': 'AAAA (IPv6 Address)', 'CAA': 'CAA (Certification Authority Authorization)', 
                                        'CNAME': 'CNAME (Alias)', 'DNAME': 'DNAME (Delegation Name)',
                                        'MX': 'MX (Mail Exchange)', 'NS': 'NS (Name Server)', 'PTR': 'PTR (Pointer)', 
                                        'SOA': 'SOA (Start of Authority)', 'SPF': 'SPF (Sender Policy Framework - as TXT)', 
                                        'SRV': 'SRV (Service Locator)', 'SSHFP': 'SSHFP (SSH Public Key Fingerprint)',
                                        'TLSA': 'TLSA (TLS Authentication)', 'TXT': 'TXT (Text)'
                                        // Removed ALIAS, CERT, LOC, NAPTR, SMIMEA for simplicity, add if needed
                                    };
                                    if (zone.name.match(/(\.in-addr\.arpa|\.ip6\.arpa)$/i)) { // Reverse zone
                                        recordTypes = {'PTR': 'PTR', 'NS': 'NS', 'SOA': 'SOA'};
                                    }
                                    data.form.find('select[name="type"]').empty();
                                    $.each(recordTypes, function(key, val) {
                                        data.form.find('select[name="type"]').append($("<option></option>").attr("value", key).text(val));
                                    });
                                    // Pre-select type if editing
                                    if (data.record && data.record.type) {
                                        data.form.find('select[name="type"]').val(data.record.type);
                                    }
                                }
                            },
                            function (childTableData) { // Function to be called when child table is opened
                                childTableData.childTable.jtable('load');
                                // Store reference to open table for search dialog
                                window.openedRecordTable = childTableData.childTable;
                                window.openedRecordTableTitle = childTableData.childTable.find('.jtable-title-text').text();
                            }
                        );
                    });
                    $container.append($editRecordsButton);

                    // Export Zone Button
                    var $exportButton = displayExportIcon(data); // data here is the zone row data
                    $container.append(' ').append($exportButton);
                    
                    return $container;
                }
            }
        },
        // Initialize the MasterZones table
        recordsLoaded: function(event, data) {
            // Apply addClear to search input after table is loaded
            $('#domsearch').addClear({
                onClear: function() {
                    $('#ZoneTableContainer').jtable('load', { domsearch: '' });
                },
                rightFocus: true
            });
        },
        // Add CSRF token to forms
        formCreated: function (event, data) {
            data.form.append('<input type="hidden" name="X-CSRF-Token" value="' + window.csrf_token + '" />');
            // Add primary_ip field specifically to the create form
            if (data.formType === 'create') {
                 data.form.find('input[name="name"]').closest('div.jtable-input-field-container').after(
                    '<div class="jtable-input-field-container">' +
                    '<div class="jtable-input-label">Primary IPv4 Address <span class="jtable-required-char">*</span></div>' +
                    '<div class="jtable-input"><input type="text" name="primary_ip" required pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" title="Enter the primary IPv4 address for this new zone (e.g., 192.168.1.100)"></div>' +
                    '</div>');
                 // Default 'kind' for WHM is Master, effectively. No need for user to select.
                 data.form.find('input[name="kind"]').val('Master'); // Or remove kind field entirely
            }
        },
        // Handle selectionChanged to open child table for records
        selectionChanged: function (event, data) {
            // This was the old logic for auto-opening child table on row click.
            // Replaced by explicit "Edit Records" button.
        }
    });

    // Removed SlaveZones jTable definition as it's not directly applicable to WHM in the same way.
    // If you have a specific need for it (e.g. managing external slave zones via a different mechanism),
    // it would need a custom implementation.

    // Import Zone jTable (hidden by default, shown as a dialog)
    <?php if ($allowzoneadd === TRUE) { ?>
    $('#ImportZoneDialog').jtable({
        title: 'Import Zone from Text',
        actions: {
            createAction: 'zones.php?action=create' // Uses the same create action
        },
        fields: {
            name: { title: 'Domain Name', inputClass: 'validate[required,custom[hostname]]' },
            primary_ip: { title: 'Primary IPv4 for New Zone', 
                input: function(data) {
                    return '<input type="text" name="primary_ip" pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" title="Enter the primary IPv4 address for this new zone." required>';
                }
            },
            <?php if (is_adminuser()) { ?>
            account: { title: 'cPanel Account', options: 'users.php?action=listoptions&e=' + $epoch, defaultValue: '<?php echo htmlspecialchars(get_sess_user()); ?>' },
            <?php } else { ?>
            account: { type: 'hidden', defaultValue: '<?php echo htmlspecialchars(get_sess_user()); ?>' },
            <?php } ?>
            // 'kind' is implicitly Master for WHM
            kind: { type: 'hidden', defaultValue: 'Master' },
            zone: { title: 'Zone Data (BIND format)', type: 'textarea', list: false, inputClass: 'validate[required]', rows:10 },
            // 'owns' (overwrite nameservers) and 'nameserver' inputs might be less relevant
            // as WHM usually sets NS records based on its configuration.
            // If you need to force specific NS records from import, they should be in the zone data.
        },
        formCreated: function (event, data) {
            data.form.append('<input type="hidden" name="X-CSRF-Token" value="' + window.csrf_token + '" />');
            data.form.find('textarea[name="zone"]').attr('placeholder', '$ORIGIN example.com.\n$TTL 86400\n@ IN SOA ns1.example.com. hostmaster.example.com. ( ... )\n@ IN NS ns1.example.com.\n@ IN NS ns2.example.com.\n@ IN A 192.0.2.1\nwww IN CNAME example.com.');
        },
        formSubmitting: function (event, data) {
            // Client-side validation could be added here for the zone data format if desired
            return true;
        },
        recordAdded: function (event, data) {
            $('#ZoneTableContainer').jtable('load'); // Reload main zone list
            $('#ImportZoneDialog').dialog('close'); // Close the dialog
        }
    });
    <?php } ?>

    // Clone Zone jTable (hidden, shown as dialog)
    <?php if (is_adminuser()) { ?>
    $('#CloneZoneDialog').jtable({
        title: 'Clone DNS Zone',
        actions: {
            createAction: 'zones.php?action=clone'
        },
        fields: {
            sourcename: { title: 'Source Domain', options: 'zones.php?action=formzonelist&e='+$epoch+'&type=master', list: false },
            destname: { title: 'New Domain Name', inputClass: 'validate[required,custom[hostname]]' },
            primary_ip: { title: 'Primary IPv4 for New Zone', 
                input: function(data) {
                    return '<input type="text" name="primary_ip" pattern="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" title="Enter the primary IPv4 address for the new cloned zone." required>';
                }
            },
            account: { title: 'cPanel Account for New Zone', options: 'users.php?action=listoptions&e='+$epoch, defaultValue: '<?php echo htmlspecialchars(get_sess_user()); ?>' },
            // Kind is implicitly Master
            kind: { type: 'hidden', defaultValue: 'Master' }
        },
        formCreated: function (event, data) {
            data.form.append('<input type="hidden" name="X-CSRF-Token" value="' + window.csrf_token + '" />');
        },
        recordAdded: function (event, data) {
            $('#ZoneTableContainer').jtable('load');
            $('#CloneZoneDialog').dialog('close');
        }
    });
    <?php } ?>


    // Search input functionality
    $('#domsearch').addClear({
        onClear: function() {
            $('#ZoneTableContainer').jtable('load', { domsearch: '' });
        },
        rightFocus: true // Focus input after clearing
    });

    var searchTimer;
    $('#domsearch').on('keyup input', function (e) {
        e.preventDefault();
        clearTimeout(searchTimer);
        searchTimer = setTimeout(function() {
            $('#ZoneTableContainer').jtable('load', {
                domsearch: $('#domsearch').val()
            });
        }, 500); // Delay before triggering search
    });

    // Password change form validation
    $('#changepw1, #changepw2').on('keyup input', function(e) {
        if ($('#changepw1').val() !== "" && $('#changepw1').val() === $('#changepw2').val() && $('#changepw1').val().length >= 8) {
            $('#changepwsubmit').prop("disabled", false);
        } else {
            $('#changepwsubmit').prop("disabled", true);
        }
    });
    $('#passwordChangeForm').submit(function() {
        if ($('#changepw1').val() !== $('#changepw2').val()) {
            alert("Passwords do not match.");
            return false;
        }
        if ($('#changepw1').val().length < 8) {
            alert("Password must be at least 8 characters long.");
            return false;
        }
        return true;
    });


    // Menu navigation
    function showSection(sectionId) {
        $('#zones, #users, #logs, #AboutMe').hide();
        $(sectionId).show();
        // If loading a jTable section, ensure it's loaded/reloaded
        if (sectionId === '#zones') {
            $('#ZoneTableContainer').jtable('load');
        } else if (sectionId === '#users' && $('#UserTableContainer').length) {
            $('#UserTableContainer').jtable('load');
        } else if (sectionId === '#logs' && $('#LogTableContainer').length) {
            $('#LogTableContainer').jtable('load', { logfile: $('#logfile_select').val() });
        }
    }

    $('#zoneadmin').click(function (e) { e.preventDefault(); showSection('#zones'); });
    <?php if (is_adminuser() && $allowusermanage === TRUE) { ?>
    $('#useradmin').click(function (e) { e.preventDefault(); showSection('#users'); });
    <?php } ?>
    <?php if (is_adminuser() && (isset($loglevel) && $loglevel > 0)) { ?>
    $('#logadmin').click(function (e) { e.preventDefault(); showSection('#logs'); });
    <?php } ?>
    <?php if (has_local_auth()) { ?>
    $('#aboutme').click(function (e) { e.preventDefault(); showSection('#AboutMe'); });
    <?php } ?>

    // Initial table loads
    $('#ZoneTableContainer').jtable('load');
    // $('#SlaveZones').jtable('load'); // Removed

    // Default to zones view
    showSection('#zones');


    <?php if (is_adminuser()) { ?>
    // User Management Table
    $('#UserTableContainer').jtable({
        title: 'Application Users',
        paging: true,
        pageSize: 20,
        sorting: true,
        defaultSorting: 'emailaddress ASC',
        actions: {
            listAction:   'users.php?action=list',
            createAction: 'users.php?action=create',
            updateAction: 'users.php?action=update',
            deleteAction: 'users.php?action=delete'
        },
        messages: {
            addNewRecord: 'Add New User',
            editRecord: 'Edit User',
            deleteConfirmation: 'This user will be deleted. Are you sure?'
        },
        fields: {
            id: { key: true, type: 'hidden' },
            emailaddress: { title: 'Login Email', width: '35%', inputClass: 'validate[required,custom[email]]' },
            cpanel_username: { title: 'cPanel Username (optional)', width: '25%', 
                input: function(data) {
                    var val = data.value || (data.record ? data.record.cpanel_username : '');
                    return '<input type="text" name="cpanel_username" value="' + htmlspecialchars(val) + '" title="Optional: Link to a cPanel username for zone permissions.">';
                }
            },
            password: {
                title: 'Password',
                type: 'password',
                list: false, // Don't show password in list
                input: function (data) { // Custom input to show placeholder for edit
                    if (data.formType === 'edit') {
                        return '<input type="password" name="password" placeholder="Leave blank to keep current password" minlength="8">';
                    } else { // Create form
                        return '<input type="password" name="password" required minlength="8">';
                    }
                }
            },
            isadmin: {
                title: 'Admin',
                width: '10%',
                type: 'checkbox',
                values: { '0': 'No', '1': 'Yes' }, // Or false/true depending on how jTable handles it
                defaultValue: '0',
                display: function(data) {
                    return (data.record.isadmin === 'Yes' || data.record.isadmin === 1 || data.record.isadmin === true) ? 'Yes' : 'No';
                }
            }
        },
        formCreated: function (event, data) {
            data.form.append('<input type="hidden" name="X-CSRF-Token" value="' + window.csrf_token + '" />');
        },
        recordAdded: function(event, data) { // After create
            // Refresh user list in case IDs or other generated data is needed
            $('#UserTableContainer').jtable('load');
            // Also refresh zone account dropdowns as they might use user list
            $epoch = Math.round(+new Date()/1000); // Update epoch to bust cache
        },
        recordUpdated: function(event, data) { // After update
            $('#UserTableContainer').jtable('load');
            $epoch = Math.round(+new Date()/1000);
        }
    });

    // Log Table
    $('#LogTableContainer').jtable({
        title: 'Application Logs (Database)',
        paging: true,
        pageSize: 50, // Show more logs per page
        sorting: true,
        defaultSorting: 'timestamp DESC', // Show newest logs first
        actions: {
            listAction: 'logs.php?action=list'
            // No create/update/delete for logs through this table directly
        },
        toolbar: {
            items: [
                {
                    text: 'Search Logs',
                    click: function() {
                        $("#searchlogsDialog").dialog({
                            modal: true, title: "Search Database Logs", width: 'auto',
                            buttons: {
                                "Search": function() {
                                    $(this).dialog('close');
                                    $('#LogTableContainer').jtable('load', {
                                        logfile: $('#logfile_select').val(), // if searching archived file
                                        user: $('#searchlogs-user').val(),
                                        entry: $('#searchlogs-entry').val()
                                    });
                                },
                                "Reset": function() {
                                    $('#searchlogs-user').val(''); $('#searchlogs-entry').val('');
                                    $(this).dialog('close');
                                    $('#LogTableContainer').jtable('load', { logfile: $('#logfile_select').val() });
                                }
                            }
                        });
                    }
                },
                <?php if(isset($allowrotatelogs) && $allowrotatelogs === TRUE && isset($logsdirectory)) { ?>
                {
                    text: 'Rotate DB Logs',
                    icon: 'img/rotate.png',
                    click: function() {
                        $("#rotatelogsDialog").dialog({
                            modal: true, title: "Confirm Log Rotation", width: 'auto',
                            buttons: {
                                "Rotate Now": function() {
                                    var dialog = $(this);
                                    // This should call a CLI script. For UI feedback, we can make an AJAX call
                                    // to a PHP script that triggers the CLI, or just inform the user.
                                    // For simplicity, we'll just inform and assume CLI is run separately.
                                    // A better way for web-triggered rotation would be a dedicated PHP action.
                                    // For now, this button is more of a reminder or could trigger a placeholder action.
                                    // Actual rotation is via CLI script `rotate-logs.php`.
                                    // We can, however, call the `logs.php?action=rotate` if we implement it there.
                                    
                                    // Let's assume logs.php can handle a 'rotate' action for demo purposes
                                    $.post('logs.php?action=rotate', {'X-CSRF-Token': window.csrf_token})
                                        .done(function(data) {
                                            if (data.Result === "OK") {
                                                alert("Log rotation process initiated (or completed if synchronous). Refreshing log list.");
                                                 $('#logfile_select').val(''); // Go back to current logs
                                                 $('#LogTableContainer').jtable('load');
                                                 // TODO: Repopulate #logfile_select if new rotated files were created
                                            } else {
                                                alert("Error initiating log rotation: " + data.Message);
                                            }
                                        })
                                        .fail(function() {
                                            alert("Failed to send log rotation request.");
                                        })
                                        .always(function() {
                                            dialog.dialog("close");
                                        });
                                },
                                "Cancel": function() { $(this).dialog("close"); }
                            }
                        });
                    }
                },
                <?php } ?>
                <?php if(isset($allowclearlogs) && $allowclearlogs === TRUE) { ?>
                {
                    icon: 'img/delete_inverted.png',
                    text: 'Clear DB Logs',
                    click: function() {
                        $("#clearlogsDialog").dialog({
                            modal: true, title: "Confirm Clear Logs", width: 'auto',
                            buttons: {
                                "Clear All Logs": function() {
                                    var dialog = $(this);
                                    $.post('logs.php?action=clear', {'X-CSRF-Token': window.csrf_token}) // POST for actions that change state
                                        .done(function(data) {
                                            if (data.Result === "OK") {
                                                $('#LogTableContainer').jtable('load', { logfile: '' }); // Reload current logs
                                            } else {
                                                alert("Error clearing logs: " + data.Message);
                                            }
                                        })
                                        .fail(function() {
                                            alert("Failed to send clear logs request.");
                                        })
                                        .always(function() {
                                            dialog.dialog("close");
                                        });
                                },
                                "Cancel": function() { $(this).dialog("close"); }
                            }
                        });
                    }
                }
                <?php } ?>
                // Download logs might be complex if it needs to fetch from file vs DB
            ]
        },
        fields: {
            id: { key: true, type: 'hidden' },
            timestamp: { title: 'Timestamp', width: '20%', displayFormat: 'yy-mm-dd HH:MM:ss' },
            user: { title: 'User', width: '15%' },
            log: { title: 'Log Entry', width: '65%', sorting: false }
        }
    });

    $('#logfile_select').change(function () {
        $('#LogTableContainer').jtable('load', {
            logfile: $(this).val(), // This param tells logs.php to load from file or DB
            user: $('#searchlogs-user').val(), // Keep search filters if any
            entry: $('#searchlogs-entry').val()
        });
    });
    <?php } // End is_adminuser() for Users and Logs tables ?>

});
</script>
</body>
</html> 
