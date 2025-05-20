<?php

// Ensure all necessary files are included.
// The exact paths might need adjustment based on your final directory structure.
$baseDir = __DIR__; // Assumes zones.php is in the root or a known directory.

// Try to determine the correct base path for includes
if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
    include_once($baseDir . '/includes/session.inc.php');
    include_once($baseDir . '/includes/misc.inc.php');
    include_once($baseDir . '/includes/class/WhmApi.php'); // Changed from PdnsApi.php
    include_once($baseDir . '/includes/class/Zone.php');
} elseif (file_exists($baseDir . '/../includes/config.inc.php')) { // If zones.php is in a subdirectory like 'actions'
    include_once($baseDir . '/../includes/config.inc.php');
    include_once($baseDir . '/../includes/session.inc.php');
    include_once($baseDir . '/../includes/misc.inc.php');
    include_once($baseDir . '/../includes/class/WhmApi.php');
    include_once($baseDir . '/../includes/class/Zone.php');
} else {
    die("Error: Could not locate essential include files. Please check paths.");
}


if (!is_csrf_safe()) {
    header('HTTP/1.1 403 Forbidden');
    jtable_respond(null, 'error', "CSRF token validation failed. Please refresh the page and try again.");
    exit;
}

// Record types that typically require their content to be quoted in zone files.
// WHM API for TXT records usually takes the unquoted string for 'txtdata'.
// The WhmApi::mapContentToWhmParams should handle any necessary (de)quoting if WHM expects raw data.
$quoteus = array('TXT', 'SPF', 'DKIM'); // SPF and DKIM are often TXT records.

/* This function is taken from:
http://pageconfig.com/post/how-to-validate-ascii-text-in-php and got fixed by
#powerdns */
function is_ascii($string) {
    return (bool) !preg_match('/[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x80-\\xff]/', $string);
}

function _valid_label($name) {
    // Allow FQDNs (ending with a dot), or relative names.
    // WHM is generally fine with FQDNs for record names.
    // '*' is allowed for wildcard records.
    // This regex might need refinement based on strictest WHM requirements.
    return is_ascii($name) && (bool) preg_match("/^([*@\-_a-z0-9](?:[\*\-_a-z0-9\.]*[a-z0-9])?)?\.?$/i", rtrim($name,'.'));
}

function _valid_domain_name_strict($name) {
    // More strict validation for a domain name itself (not record names like '*')
    return is_ascii($name) && (bool) preg_match("/^([a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\.)+[a-z0-9][-a-z0-9]{0,61}[a-z0-9]\.?$/i", rtrim($name,'.'));
}


/**
 * Decodes the JSON ID string coming from jTable for a record.
 * This ID now expected to contain 'Line' for existing records from WHM.
 */
function decode_record_id($id_string) {
    $record = json_decode($id_string, true); // true for associative array
    if (!$record
        || !isset($record['name'])
        || !isset($record['type'])
        || !isset($record['ttl'])
        // 'content_orig_whm' was used to store the original content from WHM for comparison.
        // 'Line' is crucial for WHM edits/deletes of existing records.
    ) {
        // For newly added records (not yet saved to WHM), 'Line' and 'content_orig_whm' won't exist.
        // This function is primarily for identifying existing records for edit/delete.
        // If it's a new record being identified for some client-side logic before first save,
        // it might not have 'Line'. The server-side logic for edit/delete MUST have 'Line'.
        if (!isset($record['Line']) && !(isset($_GET['action']) && in_array($_GET['action'], ['createrecord'])) ) {
             // Allow missing Line for createrecord if id is just for client-side tracking of a new row.
        }
       // jtable_respond(null, 'error', "Invalid record identifier structure: " . htmlspecialchars($id_string));
    }
    return $record;
}


// Comparison functions for sorting (can remain largely the same if structure of $a, $b is maintained)
function compareName($a, $b) {
    $aName = rtrim($a['name'], '.');
    $bName = rtrim($b['name'], '.');
    $aParts = array_reverse(explode('.', $aName));
    $bParts = array_reverse(explode('.', $bName));
    for ($i = 0; ; ++$i) {
        if (!isset($aParts[$i])) {
            return isset($bParts[$i]) ? -1 : 0;
        } else if (!isset($bParts[$i])) {
            return 1;
        }
        $cmp = strnatcasecmp($aParts[$i], $bParts[$i]);
        if ($cmp) {
            return $cmp;
        }
    }
}

function zone_compare($a, $b) {
    return compareName($a, $b); // Assuming $a and $b are zone arrays with a 'name' key
}

function rrtype_compare($a, $b) {
    $specials = array('SOA' => 0, 'NS' => 1, 'MX' => 2); // Define order
    $typeA = strtoupper($a);
    $typeB = strtoupper($b);
    $orderA = isset($specials[$typeA]) ? $specials[$typeA] : count($specials);
    $orderB = isset($specials[$typeB]) ? $specials[$typeB] : count($specials);

    if ($orderA != $orderB) {
        return $orderA - $orderB;
    }
    return strcmp($typeA, $typeB);
}

function record_compare_default($a, $b) {
    if ($cmp = compareName($a, $b)) return $cmp; // $a, $b are record arrays
    if ($cmp = rrtype_compare($a['type'], $b['type'])) return $cmp;
    $contentA = is_array($a['content']) ? implode(' ', $a['content']) : $a['content'];
    $contentB = is_array($b['content']) ? implode(' ', $b['content']) : $b['content'];
    if ($cmp = strnatcasecmp($contentA, $contentB)) return $cmp;
    return 0;
}
// Other record_compare_* functions can be defined similarly if needed by jTable sorting options.


// Database interaction for local NSEdit user/zone ownership mapping
function add_db_zone($zonename, $accountname) {
    // $accountname is the cPanel user for WHM, or your internal app user if different
    $zonename = rtrim($zonename, '.') . '.'; // Normalize
    if (valid_user($accountname) === false && !is_apiuser()) { // Allow API to potentially create users if your system supports it
        jtable_respond(null, 'error', "$accountname is not a valid user in this system.");
    }
    if (!_valid_domain_name_strict($zonename)) {
        jtable_respond(null, 'error', "$zonename is not a valid zone name.");
    }

    if (is_apiuser() && !user_exists($accountname)) { // Assuming user_exists checks your local DB
        add_user($accountname); // Assuming add_user adds to your local DB
    }

    $db = get_db();
    // Assuming 'users' table has 'cpanel_username' or similar if mapping to WHM users
    // Or 'emailaddress' if that's your primary user identifier
    $q = $db->prepare("INSERT OR REPLACE INTO zones (zone, owner) VALUES (?, (SELECT id FROM users WHERE emailaddress = ? OR cpanel_username = ? LIMIT 1))");
    $q->bindValue(1, $zonename, SQLITE3_TEXT);
    $q->bindValue(2, $accountname, SQLITE3_TEXT);
    $q->bindValue(3, $accountname, SQLITE3_TEXT); // Try matching on cpanel_username too
    $q->execute();
}

function delete_db_zone($zonename) {
    $zonename = rtrim($zonename, '.') . '.'; // Normalize
    if (!_valid_domain_name_strict($zonename)) {
        jtable_respond(null, 'error', "$zonename is not a valid zone name.");
    }
    $db = get_db();
    $q = $db->prepare("DELETE FROM zones WHERE zone = ?");
    $q->bindValue(1, $zonename, SQLITE3_TEXT);
    $q->execute();
}

function get_zone_account($zonename, $default_account) {
    $zonename = rtrim($zonename, '.') . '.'; // Normalize
    if (!_valid_domain_name_strict($zonename)) {
        // Don't jtable_respond here, this is often called internally. Log or return default.
        error_log("get_zone_account: Invalid zone name provided: " . $zonename);
        return $default_account;
    }
    $db = get_db();
    // Adapt query if your users table stores cPanel usernames
    $q = $db->prepare("SELECT u.emailaddress, u.cpanel_username FROM users u JOIN zones z ON z.owner = u.id WHERE z.zone = ?");
    $q->bindValue(1, $zonename, SQLITE3_TEXT);
    $result = $q->execute();
    $zoneinfo = $result->fetchArray(SQLITE3_ASSOC);

    if ($zoneinfo) {
        // Prefer cpanel_username if available, else emailaddress
        return !empty($zoneinfo['cpanel_username']) ? $zoneinfo['cpanel_username'] : $zoneinfo['emailaddress'];
    }
    return $default_account;
}

// Content quoting for TXT/SPF. WHM API usually wants raw data for txtdata.
// This function might be less needed if WhmApi::mapContentToWhmParams handles it.
// However, user input might still need normalization.
function quote_content_if_needed($content, $type) {
    global $quoteus; // Defined at the top
    if (in_array(strtoupper($type), $quoteus)) {
        // WHM's txtdata field typically does NOT want the surrounding quotes.
        // If content has quotes from user input, strip them.
        // If content contains spaces and is for TXT, it should be fine as is for txtdata.
        // PowerDNS needed explicit quoting for the API. WHM is different.
        // This function might now be more about ensuring the content is a single string.
        if (is_array($content)) { // Should not happen for types in $quoteus
            return implode(" ", $content);
        }
        // For TXT, WHM expects the raw string. If it needs to be "split" into multiple
        // quoted strings in the zone file for length, BIND/Named handles that.
        // The API usually takes the full logical string.
        return (string)$content; // Ensure it's a string
    }
    return $content;
}

/**
 * Checks if the current session user is authorized to manage the given Zone object.
 * The Zone object should have its cpanelUser property set.
 */
function check_account(Zone $zone) {
    if (is_adminuser()) {
        return true;
    }
    $sessionUser = get_sess_user(); // This should be the cPanel username if auth is aligned
    $zoneCpanelUser = $zone->getCpanelUser();
    
    // If zone's cPanel user isn't set, try to get it from local DB mapping
    if (empty($zoneCpanelUser)) {
        $zoneCpanelUser = get_zone_account($zone->getName(), '');
        $zone->setCpanelUser($zoneCpanelUser); // Cache it in the zone object
    }
    
    return !empty($sessionUser) && !empty($zoneCpanelUser) && $sessionUser === $zoneCpanelUser;
}


if (isset($_GET['action'])) {
    $action = $_GET['action'];
} else {
    jtable_respond(null, 'error', 'No action given');
    exit;
}

try {
    $api = new WhmApi(); // Use the new WHM API class
    global $defaults, $allowzoneadd; // From config.inc.php

    switch ($action) {

        case "list":
        // case "listslaves": // WHM doesn't distinguish master/slave easily via these APIs.
                           // All zones from listaccts/listzones are typically local/master.
            $return = array();
            $searchQuery = isset($_POST['domsearch']) ? $_POST['domsearch'] : false;
            $listedZonesData = $api->listzones($searchQuery); // Returns basic data

            foreach ($listedZonesData as $basicZoneData) {
                $zone = new Zone($basicZoneData['name']);
                $zone->setCpanelUser($basicZoneData['account']); // Account from listaccts

                // If using local DB for additional ownership/metadata, integrate here
                $localDbAccount = get_zone_account($zone->getName(), $basicZoneData['account']);
                if ($localDbAccount !== $basicZoneData['account'] && !empty($localDbAccount)) {
                    // Potentially update cPanel user if local DB is more authoritative for your app's view
                    // Or, ensure consistency during zone creation/update.
                    // For now, we prioritize the cPanel user from listaccts if available.
                     if(empty($zone->getCpanelUser()) && !empty($localDbAccount)) {
                         $zone->setCpanelUser($localDbAccount);
                     }
                }


                if (!check_account($zone)) { // check_account uses $zone->getCpanelUser()
                    continue;
                }

                // For list view, we might want serial and DNSSEC status.
                // This requires an additional call per zone, which can be slow.
                // Consider if this is essential for the list view or can be loaded on demand.
                // For now, let's try to fetch it.
                try {
                    $detailedZoneData = $api->loadzone($zone->getName()); // Calls dumpzone
                    $zone->parseWhmData($detailedZoneData); // Parses records and SOA
                    // $zone->setDnssec(...) // Placeholder: DNSSEC status needs a specific WHM API call
                    // $zone->setKeyinfo($api->getzonekeys($zone->getName())); // Placeholder
                } catch (Exception $e) {
                    writelog("Error loading details for zone {$zone->getName()} in list view: " . $e->getMessage());
                    // Continue with basic info if detailed load fails
                }
                
                $exportData = [
                    'id' => $zone->getName(), // Use domain name as ID
                    'name' => $zone->getName(),
                    'account' => $zone->getCpanelUser(),
                    'kind' => 'Master', // Assuming all are master for now
                    'serial' => $zone->getSoaSerial(),
                    'dnssec' => $zone->isDnssecEnabled(),
                    'keyinfo' => $zone->getKeyinfo(), // Will be empty based on placeholder
                    'masters' => [] // Not applicable
                ];
                array_push($return, $exportData);
            }
            usort($return, "zone_compare");
            jtable_respond($return);
            break;

        case "listrecords":
            $domainName = $_GET['zoneid']; // This is now the domain name
            $zone = new Zone($domainName);
            
            // Set cPanel user for permission check
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));
            if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to view records for {$domainName}.");
                 exit;
            }

            $whmData = $api->loadzone($domainName);
            $zone->parseWhmData($whmData);
            $records = $zone->getRecordsForDisplay(); // This now formats records for jTable

            // Filtering (remains similar, but operates on the new record structure)
            if (!empty($_POST['label'])) {
                $records = array_filter($records, function ($val) {
                    return (stripos($val['name'], $_POST['label']) !== false);
                });
            }
            if (!empty($_POST['type'])) {
                $records = array_filter($records, function ($val) {
                    return (strtoupper($val['type']) == strtoupper($_POST['type']));
                });
            }
            if (!empty($_POST['content'])) {
                $records = array_filter($records, function ($val) {
                    // 'content' field is now consistently available from formatRecordForApp
                    return (stripos($val['content'], $_POST['content']) !== false);
                });
            }

            // Sorting (remains similar)
            if (isset($_GET['jtSorting'])) {
                list($scolumn, $sorder) = preg_split("/ /", $_GET['jtSorting']);
                $compare_func = "record_compare_default";
                if (function_exists("record_compare_".$scolumn)) {
                    $compare_func = "record_compare_".$scolumn;
                }
                usort($records, $compare_func);
                if ($sorder == "DESC") {
                    $records = array_reverse($records);
                }
            } else {
                usort($records, "record_compare_default");
            }
            jtable_respond(array_values($records)); // array_values to re-index after filter
            break;

        case "delete":
            $domainName = $_POST['id']; // This is the domain name
            $zoneForCheck = new Zone($domainName);
            $zoneForCheck->setCpanelUser(get_zone_account($domainName, get_sess_user())); // Get owner for check

            if (!check_account($zoneForCheck)) {
                 jtable_respond(null, 'error', "You are not authorized to delete zone {$domainName}.");
                 exit;
            }

            $api->deletezone($domainName); // Calls killdns
            delete_db_zone($domainName); // Local DB cleanup
            writelog("Deleted zone " . $domainName);
            jtable_respond(null, 'delete');
            break;

        case "create":
            $domainName = isset($_POST['name']) ? rtrim(trim($_POST['name']), '.') : '';
            // $zonekind = isset($_POST['kind']) ? $_POST['kind'] : 'Master'; // Kind is mostly Master with WHM
            $cpanelUser = isset($_POST['account']) ? $_POST['account'] : get_sess_user(); // cPanel user for the zone
            $primaryIp = isset($_POST['primary_ip']) ? $_POST['primary_ip'] : ($defaults['default_primary_ip'] ?? '127.0.0.1'); // Get from form or config

            if (!is_adminuser() && $allowzoneadd !== true) {
                jtable_respond(null, 'error', "You are not allowed to add zones.");
                exit;
            }
            if (!_valid_domain_name_strict($domainName)) {
                jtable_respond(null, 'error', "Invalid domain name: {$domainName}. Please use a valid fully qualified domain name.");
                exit;
            }
            if (empty($cpanelUser)) {
                jtable_respond(null, 'error', "cPanel username (account) is required to create a zone.");
                exit;
            }
             if (!filter_var($primaryIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                jtable_respond(null, 'error', "A valid primary IPv4 address is required for new zones.");
                exit;
            }


            // Check local DB ownership if it matters before trying to create on WHM
            $existingOwner = get_zone_account($domainName, '');
            if (!empty($existingOwner) && $existingOwner !== $cpanelUser && !is_adminuser()) {
                 jtable_respond(null, 'error', "Zone {$domainName} is already associated with another account in this system.");
                 exit;
            }

            $zone = new Zone($domainName);
            $zone->setCpanelUser($cpanelUser);

            // If raw zone data is pasted
            if (!empty($_POST['zone'])) {
                // This requires WhmApi to have a parse_dns_zone_text method,
                // or for this script to handle it.
                // For now, assuming records will be added via template or individually.
                // $parsedZone = $api->parseZoneFileText($domainName, $_POST['zone']); // WhmApi would call parse_dns_zone
                // $zone->importParsedRecords($parsedZone['records'], $parsedZone['soa']);
                writelog("Zone creation from raw text input is not fully implemented in this version for WHM.");
                // Fall through to template/default records or expect records to be added later.
            }
            
            // Add default NS records if provided in config (WHM usually handles this based on server config)
            if (isset($defaults['nameservers']) && is_array($defaults['nameservers'])) {
                foreach ($defaults['nameservers'] as $ns) {
                    $zone->addRecord($domainName, 'NS', $ns, $defaults['ttl'] ?? 14400);
                }
            }
            // Add default MX record if in config
             if (isset($defaults['mail_servers']) && is_array($defaults['mail_servers'])) {
                foreach ($defaults['mail_servers'] as $mx) {
                     $zone->addRecord($domainName, 'MX', [$mx['priority'], $mx['host']], $defaults['ttl'] ?? 14400);
                }
            }


            // Call the savezone method in WhmApi.php
            // This will handle adddns and then adding records from $zone->getRecordsArray()
            $result = $api->savezone($zone, $cpanelUser, $primaryIp);

            add_db_zone($zone->getName(), $cpanelUser); // Update local DB

            // Apply template if selected (after initial zone creation)
            if (isset($_POST['template']) && $_POST['template'] != 'None' && !empty($templates)) {
                $templateData = null;
                foreach ($templates as $t) {
                    if ($t['name'] === $_POST['template']) {
                        $templateData = $t;
                        break;
                    }
                }
                if ($templateData) {
                    $currentZoneData = $api->loadzone($domainName);
                    $zone->parseWhmData($currentZoneData); // Reparse with live data

                    foreach ($templateData['records'] as $recordTpl) {
                        $recordName = str_replace('[ZONENAME]', $zone->getName(), $recordTpl['name']);
                        $recordContent = str_replace('[ZONENAME]', $zone->getName(), $recordTpl['content']);
                        // Potentially replace [SERVER_IP], [MAIL_SERVER_IP] from config or other sources
                        $recordContent = str_replace('[SERVER_IP]', $primaryIp, $recordContent); 
                        // Add more placeholder replacements as needed

                        // Check if a similar record (name, type) already exists from adddns defaults,
                        // if so, maybe update it or skip. For now, just add.
                        $zone->addRecord($recordName, $recordTpl['type'], $recordContent, $recordTpl['ttl'] ?? ($defaults['ttl'] ?? 14400));
                    }
                    $api->savezone($zone, $cpanelUser, $primaryIp); // Save again with template records
                }
            }
            
            $finalZoneData = $api->loadzone($domainName);
            $zone->parseWhmData($finalZoneData);

            writelog("Created zone " . $zone->getName() . " for cPanel user " . $cpanelUser);
            jtable_respond($zone->formatRecordForApp($zone->getSoaData()), 'single'); // Respond with SOA or confirmation
            break;

        case "update": // Update zone-level properties (mostly local DB account mapping)
            $domainName = $_POST['id']; // Domain name
            $zone = new Zone($domainName);
            $currentOwner = get_zone_account($domainName, '');
            $zone->setCpanelUser($currentOwner);


            if (!check_account($zone)) {
                jtable_respond(null, 'error', "You are not authorized to update zone {$domainName}.");
                exit;
            }
            
            $newAccount = isset($_POST['account']) ? $_POST['account'] : $currentOwner;

            if ($currentOwner !== $newAccount) {
                if (!is_adminuser()) {
                    jtable_respond(null, 'error', "Only administrators can change zone ownership.");
                    exit;
                }
                add_db_zone($domainName, $newAccount); // Update local DB ownership
                $zone->setCpanelUser($newAccount);
                writelog("Updated account for zone {$domainName} to {$newAccount}.");
            }

            // 'masters' field for slave zones is not applicable here for WHM in the same way.
            // If there are other zone-level properties to update via WHM API (e.g. DNSSEC enabling),
            // they would be handled here.

            // For now, this action primarily updates the local DB mapping.
            // We can re-fetch and return the zone's SOA as confirmation.
            $whmData = $api->loadzone($domainName);
            $zone->parseWhmData($whmData);
            jtable_respond($zone->formatRecordForApp($zone->getSoaData()), 'single');
            break;

        case "createrecord":
            $domainName = $_GET['zoneid'];
            $zone = new Zone($domainName);
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));

            if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to add records to {$domainName}.");
                 exit;
            }

            $recordNameInput = isset($_POST['name']) ? trim($_POST['name']) : '';
            $recordType = strtoupper($_POST['type']);
            $recordContentInput = $_POST['content']; // Raw content from user
            $recordTTL = isset($_POST['ttl']) ? (int)$_POST['ttl'] : ($defaults['ttl'] ?? 14400);
            // $recordDisabled = isset($_POST['disabled']) && $_POST['disabled'] === 'true'; // WHM handles this via comments, not directly via API record flags
            // $setptr = isset($_POST['setptr']) && $_POST['setptr'] === 'true'; // PowerDNS specific

            // Normalize record name
            $finalRecordName = $recordNameInput;
            if (empty($finalRecordName) || $finalRecordName === '@') {
                $finalRecordName = $zone->getDomainNameWithTrailingDot();
            } elseif (strpos($finalRecordName, '.') === false && $finalRecordName !== '*') { // Relative name
                $finalRecordName = $finalRecordName . '.' . $zone->getDomainNameWithTrailingDot();
            } elseif (!preg_match('/\.$/', $finalRecordName)) { // Ensure trailing dot for FQDNs
                $finalRecordName .= '.';
            }


            if (!_valid_label($finalRecordName)) {
                jtable_respond(null, 'error', "Invalid record name: {$finalRecordName}. Please only use [a-z0-9@*_/.-]");
                exit;
            }
            if (empty($recordType)) {
                jtable_respond(null, 'error', "Record type is required.");
                exit;
            }
            if (!is_ascii($recordContentInput)) { // Basic ASCII check, specific types might have stricter validation
                jtable_respond(null, 'error', "Record content should generally use ASCII characters.");
                exit;
            }
            
            // Prepare record data for WhmApi
            $recordData = [
                'name' => $finalRecordName,
                'type' => $recordType,
                'content' => $recordContentInput, // WhmApi::mapContentToWhmParams will handle type-specific fields
                'ttl' => $recordTTL,
                'class' => 'IN'
            ];

            $apiResponse = $api->addWhmRecord($domainName, $recordData);
            
            // To return the created record as jTable expects, we might need to re-fetch or parse API response
            // For now, construct a representation. A better way is to parse addWhmRecord response if it contains the record.
            // Or, reload the zone and find the record (less efficient).
            // The addWhmRecord in WhmApi returns the WHM response. We need to adapt it.
            $newRecordForTable = [
                'name' => $finalRecordName,
                'type' => $recordType,
                'content' => $recordContentInput, // This is the generic content
                'ttl' => $recordTTL,
                'disabled' => false, // New records are not disabled
                // 'Line' is not known until after a dumpzone
            ];
            $newRecordForTable['id'] = json_encode($newRecordForTable); // Create a temporary ID

            writelog("Created record for {$domainName}: " . json_encode($newRecordForTable));
            jtable_respond($newRecordForTable, 'single');
            break;

        case "editrecord":
            $domainName = $_GET['zoneid'];
            $zone = new Zone($domainName); // Create zone object for context
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));

            if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to edit records for {$domainName}.");
                 exit;
            }

            $old_record_identifier = decode_record_id($_POST['id']); // Contains name, type, content_orig_whm, Line
            
            if (!isset($old_record_identifier['Line']) || empty($old_record_identifier['Line'])) {
                jtable_respond(null, 'error', "Record line number is missing. Cannot edit. Please refresh record list.");
                exit;
            }
            $lineNumber = (int)$old_record_identifier['Line'];

            $newRecordNameInput = isset($_POST['name']) ? trim($_POST['name']) : $old_record_identifier['name'];
            $newRecordType = strtoupper($_POST['type']);
            $newRecordContentInput = $_POST['content'];
            $newRecordTTL = isset($_POST['ttl']) ? (int)$_POST['ttl'] : (int)$old_record_identifier['ttl'];

            // Normalize new record name
            $finalNewRecordName = $newRecordNameInput;
             if (empty($finalNewRecordName) || $finalNewRecordName === '@') {
                $finalNewRecordName = $zone->getDomainNameWithTrailingDot();
            } elseif (strpos($finalNewRecordName, '.') === false && $finalNewRecordName !== '*') {
                $finalNewRecordName = $finalNewRecordName . '.' . $zone->getDomainNameWithTrailingDot();
            } elseif (!preg_match('/\.$/', $finalNewRecordName)) {
                $finalNewRecordName .= '.';
            }

            if (!_valid_label($finalNewRecordName)) {
                jtable_respond(null, 'error', "Invalid new record name: {$finalNewRecordName}.");
                exit;
            }
             if (!is_ascii($newRecordContentInput)) {
                jtable_respond(null, 'error', "New record content should generally use ASCII characters.");
                exit;
            }

            $newRecordData = [
                'name' => $finalNewRecordName,
                'type' => $newRecordType,
                'content' => $newRecordContentInput,
                'ttl' => $newRecordTTL,
                'class' => 'IN' // Assuming IN class
            ];

            $apiResponse = $api->editWhmRecord($domainName, $lineNumber, $newRecordData);

            // Construct response for jTable
            $updatedRecordForTable = $newRecordData; // Base it on new data
            $updatedRecordForTable['Line'] = $lineNumber; // Keep the line number
            $updatedRecordForTable['disabled'] = false; // Assume edited records are enabled
            $updatedRecordForTable['id'] = json_encode([ // Re-create ID with new data but original line
                'name' => $finalNewRecordName,
                'type' => $newRecordType,
                'content_orig_whm' => $newRecordContentInput, // Content might have been transformed by mapContentToWhmParams
                'ttl' => $newRecordTTL,
                'Line' => $lineNumber
            ]);


            writelog("Updated record (Line {$lineNumber}) in {$domainName} from " . $_POST['id'] . " to " . $updatedRecordForTable['id']);
            jtable_respond($updatedRecordForTable, 'single');
            break;

        case "deleterecord":
            $domainName = $_GET['zoneid'];
            $zone = new Zone($domainName); // For context if needed
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));

             if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to delete records from {$domainName}.");
                 exit;
            }

            $record_to_delete_identifier = decode_record_id($_POST['id']);
            if (!isset($record_to_delete_identifier['Line']) || empty($record_to_delete_identifier['Line'])) {
                jtable_respond(null, 'error', "Record line number is missing. Cannot delete. Please refresh record list.");
                exit;
            }
            $lineNumber = (int)$record_to_delete_identifier['Line'];

            $api->removeWhmRecord($domainName, $lineNumber);

            writelog("Deleted record (Line {$lineNumber}) " . $_POST['id'] . " from {$domainName}");
            jtable_respond(null, 'delete');
            break;

        case "export":
            $domainName = $_GET['zoneid']; // Domain name
             $zoneForCheck = new Zone($domainName);
             $zoneForCheck->setCpanelUser(get_zone_account($domainName, get_sess_user()));
             if (!check_account($zoneForCheck)) {
                 jtable_respond(null, 'error', "You are not authorized to export zone {$domainName}.");
                 exit;
            }
            writelog("Exported zone " . $domainName);
            // WhmApi::exportzone returns plain text zone file
            jtable_respond($api->exportzone($domainName), 'raw'); // Use 'raw' to send plain text
            break;

        case "clone":
            $srcDomain = rtrim(trim($_POST['sourcename']), '.') . '.';
            $destDomainName = rtrim(trim($_POST['destname']), '.');
            // $destKind = isset($_POST['kind']) ? $_POST['kind'] : 'Master'; // Kind is Master
            $destCpanelUser = isset($_POST['account']) ? $_POST['account'] : get_sess_user();
            $destPrimaryIp =  isset($_POST['primary_ip']) ? $_POST['primary_ip'] : ($defaults['default_primary_ip'] ?? '127.0.0.1');


            if (!is_adminuser() && $allowzoneadd !== true) {
                jtable_respond(null, 'error', "You are not allowed to add (clone) zones.");
                exit;
            }
            if (!_valid_domain_name_strict($destDomainName)) {
                jtable_respond(null, 'error', "Invalid destination zone name: {$destDomainName}");
                exit;
            }
             if (empty($destCpanelUser)) {
                jtable_respond(null, 'error', "cPanel username (account) is required for the new cloned zone.");
                exit;
            }

            $srcZone = new Zone($srcDomain);
            $srcZone->setCpanelUser(get_zone_account($srcDomain, get_sess_user())); // For permission check on source
            if (!check_account($srcZone)) {
                jtable_respond(null, 'error', "You are not authorized to read source zone {$srcDomain} for cloning.");
                exit;
            }
            
            $srcWhmData = $api->loadzone($srcDomain);
            $srcZone->parseWhmData($srcWhmData);
            
            // 1. Create the new destination zone (basic)
            $api->createWhmZone($destDomainName, $destPrimaryIp, $destCpanelUser);
            writelog("Created basic destination zone {$destDomainName} for cloning.");

            // 2. Add records from source to destination
            // We need to be careful about SOA and NS records from the source.
            // WHM's adddns creates its own SOA and NS. We should typically replace those
            // or add others. For simplicity, we'll add all non-SOA records from source,
            // adapting names.
            $recordsToAdd = [];
            foreach ($srcZone->getRecordsArray() as $record) { // getRecordsArray gives generic content
                if (strtoupper($record['type']) === 'SOA') {
                    continue; // Skip original SOA, adddns creates a new one. We could edit it later if needed.
                }
                
                $newName = $record['name'];
                // Replace occurrences of source domain in record name with dest domain
                $newName = preg_replace('/' . preg_quote(rtrim($srcDomain,'.'), '/') . '(\.?)$/', rtrim($destDomainName,'.') . "$1", $newName);
                if ($record['name'] === $srcDomain) { // Apex record
                    $newName = rtrim($destDomainName,'.') . '.';
                }


                $recordDataForAdd = [
                    'name' => $newName,
                    'type' => $record['type'],
                    'content' => $record['content'], // Generic content
                    'ttl' => $record['ttl'],
                    'class' => $record['class'] ?? 'IN'
                ];
                
                // If it's an NS record for the apex, and it points to the source domain's NS,
                // it might need special handling or might be correctly set by WHM's adddns.
                // For now, we add them if they are not the ones WHM would auto-create.
                // This part can be complex if source NS records are like ns1.sourcedomain.com.
                
                try {
                    $api->addWhmRecord($destDomainName, $recordDataForAdd);
                } catch (Exception $e) {
                    writelog("Warning: Could not add record " . json_encode($recordDataForAdd) . " to {$destDomainName} during clone: " . $e->getMessage());
                }
            }
            
            add_db_zone($destDomainName, $destCpanelUser); // Local DB mapping

            $finalDestZoneData = $api->loadzone($destDomainName);
            $destZoneObj = new Zone($destDomainName);
            $destZoneObj->parseWhmData($finalDestZoneData);

            writelog("Cloned zone {$srcDomain} to {$destDomainName} for cPanel user {$destCpanelUser}.");
            jtable_respond($destZoneObj->formatRecordForApp($destZoneObj->getSoaData()), 'single'); // Return SOA of new zone
            break;

        // Template related actions might need adjustment if templates define specific NS records
        // that conflict with WHM's defaults. For now, assuming they are mostly for other record types.
        case "gettemplatenameservers": // This is likely less relevant with WHM managing NS typically
            $ret = array();
            $type = $_GET['prisec']; // 'pri' or 'sec'

            if (empty($templates)) { echo ""; exit(0); } // Global $templates from config

            foreach ($templates as $template) {
                if ($template['name'] !== $_GET['template']) continue;
                $rc = 0;
                foreach ($template['records'] as $record) {
                    if (strtoupper($record['type']) == "NS") {
                        if (($type == 'pri' && $rc == 0) || ($type == 'sec' && $rc == 1)) {
                            // Content here is the nameserver hostname
                            echo htmlspecialchars($record['content']);
                            exit(0);
                        }
                        $rc++;
                    }
                }
            }
            echo "";
            exit(0);
            break;

        case "getformnameservers": // Also less relevant if WHM handles NS
             if (empty($templates)) { exit(0); }
             foreach ($templates as $template) {
                if ($template['name'] !== $_GET['template']) continue;
                $inputs = array();
                foreach ($template['records'] as $record) {
                    if (strtoupper($record['type']) == "NS" && !in_array($record['content'], $inputs)) {
                        array_push($inputs, $record['content']);
                        echo '<input type="text" name="nameserver[]" value="'.htmlspecialchars($record['content']).'" readonly /><br />';
                    }
                }
            }
            exit(0);
            break;

        case "formzonelist": // List zones for a dropdown (e.g., for cloning source)
            $listedZones = $api->listzones(); // Basic list
            $ret = array();
            foreach ($listedZones as $basicZoneData) {
                $zoneForCheck = new Zone($basicZoneData['name']);
                $zoneForCheck->setCpanelUser(get_zone_account($basicZoneData['name'], $basicZoneData['account']));

                if (!check_account($zoneForCheck)) {
                    continue;
                }
                // Assuming all zones from WHM are 'Master' for this tool's purpose
                array_push($ret, array(
                    'DisplayText' => $basicZoneData['name'],
                    'Value'       => $basicZoneData['name'] // Use domain name as value
                ));
            }
            usort($ret, function($a, $b) { return strnatcasecmp($a['DisplayText'], $b['DisplayText']); });
            jtable_respond($ret, 'options');
            break;

        default:
            jtable_respond(null, 'error', 'No such action: ' . htmlspecialchars($action));
            break;
    }
} catch (Exception $e) {
    // Log the full exception details for debugging
    writelog("Error in zones.php action '{$action}': " . $e->getMessage() . "\nTrace: " . $e->getTraceAsString());
    // Provide a user-friendly error message
    jtable_respond(null, 'error', "An API error occurred: " . htmlspecialchars($e->getMessage()));
}

?>
