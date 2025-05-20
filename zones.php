<?php

// Ensure all necessary files are included.
// The exact paths might need adjustment based on your final directory structure.
$baseDir = __DIR__; // Assumes zones.php is in the root or a known directory.

// Try to determine the correct base path for includes
if (file_exists($baseDir . '/includes/config.inc.php')) {
    include_once($baseDir . '/includes/config.inc.php');
    include_once($baseDir . '/includes/session.inc.php');
    include_once($baseDir . '/includes/misc.inc.php'); // misc.inc.php now contains is_ascii, _valid_label, add_db_zone etc.
    include_once($baseDir . '/includes/class/WhmApi.php'); 
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

// Functions is_ascii(), _valid_label(), _valid_domain_name_strict() are now in misc.inc.php
// Functions add_db_zone(), delete_db_zone(), get_zone_account() are now in misc.inc.php


/**
 * Decodes the JSON ID string coming from jTable for a record.
 * This ID now expected to contain 'Line' for existing records from WHM.
 */  
     
if (isset($_GET['action'])) {
    $action = $_GET['action'];
} else {
    jtable_respond(null, 'error', 'No action given');
    exit;
}

try {
    $api = new WhmApi(); // Use the new WHM API class
    global $defaults, $allowzoneadd, $templates; // From config.inc.php

    switch ($action) {

        case "list":
            $return = array();
            $searchQuery = isset($_POST['domsearch']) ? $_POST['domsearch'] : false;
            $listedZonesData = $api->listzones($searchQuery); 

            foreach ($listedZonesData as $basicZoneData) {
                $zone = new Zone($basicZoneData['name']);
                $zone->setCpanelUser($basicZoneData['account']); 

                $localDbAccount = get_zone_account($zone->getName(), $basicZoneData['account']);
                if ($localDbAccount !== $basicZoneData['account'] && !empty($localDbAccount)) {
                     if(empty($zone->getCpanelUser()) && !empty($localDbAccount)) {
                         $zone->setCpanelUser($localDbAccount);
                     }
                }

                if (!check_account($zone)) { 
                    continue;
                }
                
                $is_dnssec_enabled_for_zone = false; 
                $key_info_for_zone = [];

                try {
                    $detailedZoneData = $api->loadzone($zone->getName()); 
                    $zone->parseWhmData($detailedZoneData); 
                    
                    $key_info_for_zone = $api->getzonekeys($zone->getName());
                    if (!empty($key_info_for_zone)) {
                        foreach($key_info_for_zone as $key) {
                            if (isset($key['active']) && $key['active']) {
                                $is_dnssec_enabled_for_zone = true;
                                break;
                            }
                        }
                    }
                    $zone->setDnssec($is_dnssec_enabled_for_zone);
                    $zone->setKeyinfo($key_info_for_zone);

                } catch (Exception $e) {
                    writelog("Error loading details for zone {$zone->getName()} in list view: " . $e->getMessage());
                }
                
                $exportData = [
                    'id' => $zone->getName(), 
                    'name' => $zone->getName(),
                    'account' => $zone->getCpanelUser(),
                    'kind' => 'Master', 
                    'serial' => $zone->getSoaSerial(),
                    'dnssec' => $zone->isDnssecEnabled(), 
                    'keyinfo' => $zone->getKeyinfo(),   
                    'masters' => [] 
                ];
                array_push($return, $exportData);
            }
            usort($return, "zone_compare");
            jtable_respond($return);
            break;

        case "getzonekeys": 
            $domainName = isset($_REQUEST['zoneid']) ? $_REQUEST['zoneid'] : null; 
            if (empty($domainName)) {
                jtable_respond(null, 'error', "Zone name (zoneid) is required for getzonekeys.");
                exit;
            }
            $zoneForCheck = new Zone($domainName);
            $zoneForCheck->setCpanelUser(get_zone_account($domainName, get_sess_user()));
            if (!check_account($zoneForCheck)) {
                 jtable_respond(null, 'error', "You are not authorized to view DNSSEC keys for {$domainName}.");
                 exit;
            }
            $keys = $api->getzonekeys($domainName);
            jtable_respond($keys); 
            break;


        case "listrecords":
            $domainName = $_GET['zoneid']; 
            $zone = new Zone($domainName);
            
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));
            if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to view records for {$domainName}.");
                 exit;
            }

            $whmData = $api->loadzone($domainName);
            $zone->parseWhmData($whmData);
            $records = $zone->getRecordsForDisplay(); 

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
                    return (stripos($val['content'], $_POST['content']) !== false);
                });
            }

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
            jtable_respond(array_values($records)); 
            break;

        case "delete":
            $domainName = $_POST['id']; 
            $zoneForCheck = new Zone($domainName);
            $zoneForCheck->setCpanelUser(get_zone_account($domainName, get_sess_user())); 

            if (!check_account($zoneForCheck)) {
                 jtable_respond(null, 'error', "You are not authorized to delete zone {$domainName}.");
                 exit;
            }

            $api->deletezone($domainName); 
            delete_db_zone($domainName); 
            writelog("Deleted zone " . $domainName);
            jtable_respond(null, 'delete');
            break;

        case "create":
            $domainName = isset($_POST['name']) ? rtrim(trim($_POST['name']), '.') : '';
            $cpanelUser = isset($_POST['account']) ? $_POST['account'] : get_sess_user();
            $primaryIp = isset($_POST['primary_ip']) ? $_POST['primary_ip'] : ($defaults['default_primary_ip'] ?? '');
            $rawZoneText = isset($_POST['zone']) ? $_POST['zone'] : null; // From import form
            $overwriteNameservers = isset($_POST['owns']) && $_POST['owns'] == '1';


            if (!is_adminuser() && $allowzoneadd !== TRUE) {
                jtable_respond(null, 'error', "You are not allowed to add zones.");
                exit;
            }
            if (!_valid_domain_name_strict($domainName)) {
                jtable_respond(null, 'error', "Invalid domain name: {$domainName}. Please use a valid FQDN.");
                exit;
            }
            if (empty($cpanelUser)) {
                jtable_respond(null, 'error', "cPanel username (account) is required.");
                exit;
            }
            if (empty($primaryIp) || !filter_var($primaryIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                jtable_respond(null, 'error', "A valid primary IPv4 address is required for new zones.");
                exit;
            }

            $existingOwner = get_zone_account($domainName, '');
            if (!empty($existingOwner) && $existingOwner !== $cpanelUser && !is_adminuser()) {
                 jtable_respond(null, 'error', "Zone {$domainName} is already associated with another account in this system.");
                 exit;
            }

            // 1. Create the basic zone on WHM server
            $api->createWhmZone($domainName, $primaryIp, $cpanelUser);
            writelog("Basic WHM zone {$domainName} created for user {$cpanelUser} with IP {$primaryIp}.");

            $zone = new Zone($domainName); // NSEdit's Zone object
            $zone->setCpanelUser($cpanelUser);

            if (!empty($rawZoneText)) {
                writelog("Importing records from provided zone text for {$domainName}.");
                try {
                    $parsedZoneData = $api->parseZoneFileText($domainName, $rawZoneText); // Method in WhmApi.php
                    
                    if (isset($parsedZoneData['records']) && is_array($parsedZoneData['records'])) {
                        foreach ($parsedZoneData['records'] as $parsedRecord) {
                            $type = strtoupper($parsedRecord['type'] ?? '');
                            if ($type === 'SOA') continue; // Skip SOA from import
                            if ($type === 'NS' && !$overwriteNameservers) {
                                writelog("Skipping NS record from import for {$domainName} (overwrite not specified).");
                                continue;
                            }
                            // Ensure content is correctly structured for addWhmRecord
                            $contentForApi = $parsedRecord['content'] ?? (isset($parsedRecord['data']) ? (is_array($parsedRecord['data']) ? implode(' ', $parsedRecord['data']) : $parsedRecord['data']) : '');
                            if ($type === 'MX' && isset($parsedRecord['preference']) && isset($parsedRecord['exchange'])) {
                                $contentForApi = [$parsedRecord['preference'], $parsedRecord['exchange']];
                            } 

                            $recordDataForAdd = [
                                'name'    => $parsedRecord['name'] ?? $domainName,
                                'type'    => $type,
                                'ttl'     => isset($parsedRecord['ttl']) ? (int)$parsedRecord['ttl'] : ($defaults['ttl'] ?? 14400),
                                'class'   => $parsedRecord['class'] ?? 'IN',
                                'content' => $contentForApi
                            ];
                            try {
                                $api->addWhmRecord($domainName, $recordDataForAdd);
                                writelog("Added imported record to {$domainName}: {$recordDataForAdd['name']} {$recordDataForAdd['type']}");
                            } catch (Exception $eAddRec) {
                                writelog("Error adding imported record {$recordDataForAdd['name']} {$recordDataForAdd['type']} to {$domainName}: " . $eAddRec->getMessage());
                            }
                        }
                    } else {
                        writelog("No records found or error parsing provided zone text for {$domainName}.");
                    }
                } catch (Exception $eParse) {
                    writelog("Error processing provided zone text for {$domainName}: " . $eParse->getMessage());
                }
            } else { // No raw zone text, apply defaults and/or template
                $recordsToInitiallyAdd = [];
                if (isset($defaults['nameservers']) && is_array($defaults['nameservers']) && $overwriteNameservers) { // only apply default NS if overwriting
                    foreach ($defaults['nameservers'] as $ns) {
                        $recordsToInitiallyAdd[] = ['name' => $domainName, 'type' => 'NS', 'content' => $ns, 'ttl' => $defaults['ttl'] ?? 14400, 'class' => 'IN'];
                    }
                }
                if (isset($defaults['mail_servers']) && is_array($defaults['mail_servers'])) {
                    foreach ($defaults['mail_servers'] as $mx) {
                        $mx_content = (isset($mx['priority']) ? $mx['priority'] . ' ' : '10 ') . $mx['host'];
                        $recordsToInitiallyAdd[] = ['name' => $domainName, 'type' => 'MX', 'content' => $mx_content, 'ttl' => $defaults['ttl'] ?? 14400, 'class' => 'IN'];
                    }
                }
                foreach($recordsToInitiallyAdd as $recData) {
                    try { $api->addWhmRecord($domainName, $recData); } catch (Exception $e) { writelog("Error adding default record for {$domainName}: ".$e->getMessage());}
                }
            }
            
            add_db_zone($domainName, $cpanelUser); 

            if (isset($_POST['template']) && $_POST['template'] != 'None' && !empty($templates)) {
                $templateData = null;
                foreach ($templates as $t) {
                    if ($t['name'] === $_POST['template']) { $templateData = $t; break; }
                }
                if ($templateData && isset($templateData['records'])) {
                    // For applying a template, it's better to fetch current state, then add template records
                    // $currentZoneData = $api->loadzone($domainName);
                    // $zone->parseWhmData($currentZoneData); // This would overwrite any imported records in $zone object

                    foreach ($templateData['records'] as $recordTpl) {
                        $recordName = str_replace('[ZONENAME]', rtrim($domainName,'.'), $recordTpl['name']);
                        $recordContent = str_replace('[ZONENAME]', rtrim($domainName,'.'), $recordTpl['content']);
                        $recordContent = str_replace('[SERVER_IP]', $primaryIp, $recordContent); 
                        
                        $recordDataForAdd = [
                            'name' => $recordName, 'type' => $recordTpl['type'], 
                            'content' => $recordContent, 
                            'ttl' => $recordTpl['ttl'] ?? ($defaults['ttl'] ?? 14400),
                            'class' => 'IN'
                        ];
                         try { $api->addWhmRecord($domainName, $recordDataForAdd); } catch (Exception $e) { writelog("Error adding template record for {$domainName}: ".$e->getMessage());}
                    }
                }
            }
            
            $finalZoneData = $api->loadzone($domainName);
            $zone->parseWhmData($finalZoneData);
            writelog("Finished creating/importing zone " . $zone->getName() . " for cPanel user " . $cpanelUser);
            $soaDisplay = $zone->formatRecordForApp($zone->getSoaData() ?: ['name'=>$zone->getName(), 'type'=>'SOA', 'content'=>'Default SOA', 'ttl'=>3600]);
            jtable_respond($soaDisplay, 'single'); 
            break;

        case "update": 
            $domainName = $_POST['id']; 
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
                add_db_zone($domainName, $newAccount); 
                $zone->setCpanelUser($newAccount);
                writelog("Updated account for zone {$domainName} to {$newAccount}.");
            }
            
            $whmData = $api->loadzone($domainName);
            $zone->parseWhmData($whmData);
            $soaDisplay = $zone->formatRecordForApp($zone->getSoaData() ?: ['name'=>$zone->getName(), 'type'=>'SOA', 'content'=>'Default SOA', 'ttl'=>3600]);
            jtable_respond($soaDisplay, 'single');
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
            $recordContentInput = $_POST['content']; 
            $recordTTL = isset($_POST['ttl']) ? (int)$_POST['ttl'] : ($defaults['ttl'] ?? 14400);
            
            $finalRecordName = $recordNameInput;
            if (empty($finalRecordName) || $finalRecordName === '@') {
                $finalRecordName = $zone->getDomainNameWithTrailingDot();
            } elseif (strpos($finalRecordName, '.') === false && $finalRecordName !== '*') { 
                $finalRecordName = $finalRecordName . '.' . $zone->getDomainNameWithTrailingDot();
            } elseif (!preg_match('/\.$/', $finalRecordName)) { 
                $finalRecordName .= '.';
            }

            if (!_valid_label($finalRecordName)) {
                jtable_respond(null, 'error', "Invalid record name: {$finalRecordName}. Please use [a-z0-9@*_/.-]");
                exit;
            }
            if (empty($recordType)) {
                jtable_respond(null, 'error', "Record type is required.");
                exit;
            }
            
            $recordData = [
                'name' => $finalRecordName,
                'type' => $recordType,
                'content' => quote_content_if_needed($recordContentInput, $recordType),
                'ttl' => $recordTTL,
                'class' => 'IN'
            ];

            $apiResponse = $api->addWhmRecord($domainName, $recordData);
            
            $newRecordForTable = $recordData; 
            $newRecordForTable['id'] = json_encode($newRecordForTable); 

            writelog("Created record for {$domainName}: " . json_encode($newRecordForTable));
            jtable_respond($newRecordForTable, 'single');
            break;

        case "editrecord":
            $domainName = $_GET['zoneid'];
            $zone = new Zone($domainName); 
            $zone->setCpanelUser(get_zone_account($domainName, get_sess_user()));

            if (!check_account($zone)) {
                 jtable_respond(null, 'error', "You are not authorized to edit records for {$domainName}.");
                 exit;
            }

            $old_record_identifier = decode_record_id($_POST['id']); 
            
            if (!isset($old_record_identifier['Line']) || empty($old_record_identifier['Line'])) {
                jtable_respond(null, 'error', "Record line number is missing. Cannot edit. Please refresh record list.");
                exit;
            }
            $lineNumber = (int)$old_record_identifier['Line'];

            $newRecordNameInput = isset($_POST['name']) ? trim($_POST['name']) : $old_record_identifier['name'];
            $newRecordType = strtoupper($_POST['type']);
            $newRecordContentInput = $_POST['content'];
            $newRecordTTL = isset($_POST['ttl']) ? (int)$_POST['ttl'] : (int)$old_record_identifier['ttl'];

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
            
            $newRecordData = [
                'name' => $finalNewRecordName,
                'type' => $newRecordType,
                'content' => quote_content_if_needed($newRecordContentInput, $newRecordType),
                'ttl' => $newRecordTTL,
                'class' => 'IN' 
            ];

            $apiResponse = $api->editWhmRecord($domainName, $lineNumber, $newRecordData);

            $updatedRecordForTable = $newRecordData; 
            $updatedRecordForTable['Line'] = $lineNumber; 
            $updatedRecordForTable['id'] = json_encode([ 
                'name' => $finalNewRecordName,
                'type' => $newRecordType,
                'content_orig_whm' => $newRecordContentInput, 
                'ttl' => $newRecordTTL,
                'Line' => $lineNumber
            ]);

            writelog("Updated record (Line {$lineNumber}) in {$domainName} from " . $_POST['id'] . " to " . $updatedRecordForTable['id']);
            jtable_respond($updatedRecordForTable, 'single');
            break;

        case "deleterecord":
            $domainName = $_GET['zoneid'];
            $zone = new Zone($domainName); 
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
            $domainName = $_GET['zoneid']; 
             $zoneForCheck = new Zone($domainName);
             $zoneForCheck->setCpanelUser(get_zone_account($domainName, get_sess_user()));
             if (!check_account($zoneForCheck)) {
                 jtable_respond(null, 'error', "You are not authorized to export zone {$domainName}.");
                 exit;
            }
            writelog("Exported zone " . $domainName);
            jtable_respond($api->exportzone($domainName), 'raw'); 
            break;

        case "clone":
            $srcDomain = rtrim(trim($_POST['sourcename']), '.') . '.';
            $destDomainName = rtrim(trim($_POST['destname']), '.');
            $destCpanelUser = isset($_POST['account']) ? $_POST['account'] : get_sess_user();
            $destPrimaryIp =  isset($_POST['primary_ip']) ? $_POST['primary_ip'] : ($defaults['default_primary_ip'] ?? '');


            if (!is_adminuser() && $allowzoneadd !== TRUE) {
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
            if (empty($destPrimaryIp) || !filter_var($destPrimaryIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                jtable_respond(null, 'error', "A valid primary IPv4 for the new zone is required for cloning.");
                exit;
            }


            $srcZone = new Zone($srcDomain);
            $srcZone->setCpanelUser(get_zone_account($srcDomain, get_sess_user())); 
            if (!check_account($srcZone)) {
                jtable_respond(null, 'error', "You are not authorized to read source zone {$srcDomain} for cloning.");
                exit;
            }
            
            $srcWhmData = $api->loadzone($srcDomain);
            $srcZone->parseWhmData($srcWhmData);
            
            $api->createWhmZone($destDomainName, $destPrimaryIp, $destCpanelUser);
            writelog("Created basic destination zone {$destDomainName} for cloning.");

            $destZoneForRecords = new Zone($destDomainName); // Create a new Zone object for the destination

            foreach ($srcZone->getRecordsArray() as $record) { 
                if (strtoupper($record['type']) === 'SOA') {
                    continue; 
                }
                
                $newName = $record['name'];
                $normalizedSrcDomain = rtrim($srcDomain, '.');
                $normalizedDestDomain = rtrim($destDomainName, '.');

                if (strtolower(rtrim($newName, '.')) === strtolower($normalizedSrcDomain)) {
                    $newName = $normalizedDestDomain . '.';
                } else {
                    $newName = preg_replace('/' . preg_quote($normalizedSrcDomain, '/') . '(\.?)$/i', $normalizedDestDomain . "$1", $newName);
                }
                
                $recordDataForAdd = [
                    'name' => $newName,
                    'type' => $record['type'],
                    'content' => $record['content'], 
                    'ttl' => $record['ttl'],
                    'class' => $record['class'] ?? 'IN'
                ];
                
                try {
                    // Add to the local Zone object first, then save all at once if using WhmApi::savezone
                    // Or add one by one via API
                     $api->addWhmRecord($destDomainName, $recordDataForAdd);
                } catch (Exception $e) {
                    writelog("Warning: Could not add record " . json_encode($recordDataForAdd) . " to {$destDomainName} during clone: " . $e->getMessage());
                }
            }
            
            add_db_zone($destDomainName, $destCpanelUser); 

            $finalDestZoneData = $api->loadzone($destDomainName);
            $destZoneObj = new Zone($destDomainName);
            $destZoneObj->parseWhmData($finalDestZoneData);

            writelog("Cloned zone {$srcDomain} to {$destDomainName} for cPanel user {$destCpanelUser}.");
            $soaDisplayClone = $destZoneObj->formatRecordForApp($destZoneObj->getSoaData() ?: ['name'=>$destZoneObj->getName(), 'type'=>'SOA', 'content'=>'Default SOA', 'ttl'=>3600]);
            jtable_respond($soaDisplayClone, 'single'); 
            break;

        case "gettemplatenameservers": 
            $ret = array();
            $type = $_GET['prisec']; 

            if (empty($templates)) { echo ""; exit(0); } 

            foreach ($templates as $template) {
                if ($template['name'] !== $_GET['template']) continue;
                $rc = 0;
                foreach ($template['records'] as $record) {
                    if (strtoupper($record['type']) == "NS") {
                        if (($type == 'pri' && $rc == 0) || ($type == 'sec' && $rc == 1)) {
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

        case "getformnameservers": 
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

        case "formzonelist": 
            $listedZones = $api->listzones(); 
            $ret = array();
            foreach ($listedZones as $basicZoneData) {
                $zoneForCheck = new Zone($basicZoneData['name']);
                $zoneForCheck->setCpanelUser(get_zone_account($basicZoneData['name'], $basicZoneData['account']));

                if (!check_account($zoneForCheck)) {
                    continue;
                }
                array_push($ret, array(
                    'DisplayText' => $basicZoneData['name'],
                    'Value'       => $basicZoneData['name'] 
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
    writelog("Error in zones.php action '{$action}': " . $e->getMessage() . "\nTrace: " . $e->getTraceAsString());
    jtable_respond(null, 'error', "An API error occurred: " . htmlspecialchars($e->getMessage()));
}

?> 