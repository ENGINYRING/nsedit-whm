<?php

if (file_exists(__DIR__ . '/../config.inc.php')) {
    include_once(__DIR__ . '/../config.inc.php');
} elseif (file_exists(__DIR__ . '/../../includes/config.inc.php')) {
    include_once(__DIR__ . '/../../includes/config.inc.php');
}

if (file_exists(__DIR__ . '/ApiHandler.php')) {
    include_once(__DIR__ . '/ApiHandler.php');
} elseif (file_exists(__DIR__ . '/../../includes/class/ApiHandler.php')) {
    include_once(__DIR__ . '/../../includes/class/ApiHandler.php');
}


class WhmApi {
    private $apiHandler;
    private $apiVersion = '1'; // WHM API version

    // Mapping of generic record content field to WHM API specific field names
    private $whmRecordContentFields = [
        'A'     => 'address',
        'AAAA'  => 'address',
        'CNAME' => 'cname',
        'MX'    => ['preference', 'exchange'], // MX needs special handling
        'TXT'   => 'txtdata',
        'SRV'   => ['priority', 'weight', 'port', 'target'], // SRV needs special handling
        'NS'    => 'nsdname',
        'PTR'   => 'ptrdname',
        'SOA'   => ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'], // SOA is complex
        'CAA'   => ['flags', 'tag', 'value'],
        // Add other types as needed: DS, DNSKEY, SPF (often as TXT), etc.
    ];


    public function __construct() {
        $this->apiHandler = new ApiHandler();
    }

    /**
     * Makes a generic call to the WHM API.
     *
     * @param string $function The WHM API function name (e.g., "listaccts").
     * @param array $params Associative array of parameters for the API call.
     * @param string $method HTTP method (GET, POST). Defaults to GET.
     * @return array|null The decoded JSON response from the API or null on failure.
     * @throws Exception If the API call fails.
     */
    private function callWhmApi($function, $params = array(), $method = 'GET') {
        $this->apiHandler->method = strtoupper($method);
        
        // Always add api.version
        $params['api.version'] = $this->apiVersion;
        
        $queryString = http_build_query($params);
        // Ensure the function name doesn't have leading/trailing slashes from previous logic
        $this->apiHandler->url = trim($function, '/') . '?' . $queryString;


        if ($this->apiHandler->method === 'POST') {
            // For WHM API 1, POST data is often like GET parameters (application/x-www-form-urlencoded)
            // The ApiHandler's go() method now handles http_build_query for array content in POST.
            // If $params were intended for the body, they should be passed to $this->apiHandler->content
            // For GET-like POSTs, they are already in $this->apiHandler->url
            $this->apiHandler->content = $params; // Let ApiHandler decide how to use it for POST
        } else {
            $this->apiHandler->content = null; 
        }

        try {
            $this->apiHandler->call();
            // WHM API typically has data under a 'data' key or directly,
            // and metadata for status.
            if (isset($this->apiHandler->json['metadata']['result']) && $this->apiHandler->json['metadata']['result'] == 1) {
                return isset($this->apiHandler->json['data']) ? $this->apiHandler->json['data'] : $this->apiHandler->json; // Return 'data' if exists, else full json
            } elseif (isset($this->apiHandler->json['result']) && $this->apiHandler->json['result'] == 1 && isset($this->apiHandler->json['data'])) {
                // Some cPanel API calls (like UAPI via WHM) might have a slightly different structure
                return $this->apiHandler->json['data'];
            } elseif (isset($this->apiHandler->json['status']) && $this->apiHandler->json['status'] == 1 && isset($this->apiHandler->json['payload'])) {
                // Another observed successful structure (e.g. export_zone_files)
                 return $this->apiHandler->json['payload'];
            } elseif (isset($this->apiHandler->json['data']['status']) && $this->apiHandler->json['data']['status'] == 1 && isset($this->apiHandler->json['data']['payload'])) {
                 // Yet another observed structure
                 return $this->apiHandler->json['data']['payload'];
            } elseif (isset($this->apiHandler->json['metadata']['result']) && $this->apiHandler->json['metadata']['result'] == 0) {
                $reason = isset($this->apiHandler->json['metadata']['reason']) ? $this->apiHandler->json['metadata']['reason'] : 'Unknown error';
                throw new Exception("WHM API Error for {$function}: " . $reason);
            }
            // If metadata.result is not present, but http code was 200, it might be a direct data response
            if ($this->apiHandler->last_http_code >= 200 && $this->apiHandler->last_http_code < 300 && isset($this->apiHandler->json)) {
                // Check if it's a simple array of data without 'data' or 'payload' wrapper
                if (is_array($this->apiHandler->json) && (isset($this->apiHandler->json[0]) || empty($this->apiHandler->json))) {
                    return $this->apiHandler->json;
                }
            }
            // Fallback if structure is unexpected but call seemed successful
            if ($this->apiHandler->last_http_code >= 200 && $this->apiHandler->last_http_code < 300 && $this->apiHandler->json !== null) {
                return $this->apiHandler->json;
            }
            throw new Exception("WHM API call to {$function} failed or returned unexpected structure. HTTP Code: {$this->apiHandler->last_http_code}. Response: " . substr(json_encode($this->apiHandler->json), 0, 200));
        } catch (Exception $e) {
            // Log the error or handle it more gracefully if needed
            // error_log("WhmApi Error: " . $e->getMessage());
            throw $e; // Re-throw the exception
        }
    }

    /**
     * Lists DNS zones.
     *
     * @param string|false $searchQuery Optional search query for domain names.
     * @return array List of zone data arrays.
     */
    public function listzones($searchQuery = false) {
        $zones = array();
        $params = array();
        $apiFunction = 'listaccts';
        if ($searchQuery) {
            $params['search'] = $searchQuery;
            $params['searchtype'] = 'domain';
        }

        $responseData = $this->callWhmApi($apiFunction, $params);

        if (isset($responseData['acct']) && is_array($responseData['acct'])) {
            foreach ($responseData['acct'] as $account) {
                if (empty($account['domain'])) continue;
                $zoneData = [
                    'id' => $account['domain'], 
                    'name' => $account['domain'],
                    'account' => $account['user'], 
                    'kind' => 'Master', 
                    'url' => null, 
                    'serial' => null, 
                    'dnssec' => false, 
                    'masters' => [], 
                ];
                $zones[] = $zoneData;
            }
        }
        return $zones;
    }

    /**
     * Loads detailed information for a specific zone (domain).
     *
     * @param string $domainName The domain name.
     * @return array|null Zone data including records, or null on failure.
     */
    public function loadzone($domainName) {
        $params = ['domain' => $domainName];
        // dumpzone typically returns { "metadata": { ... }, "data": { "soa": { ... }, "zone": [ ...records... ] } }
        $responseData = $this->callWhmApi('dumpzone', $params);
        return $responseData; // The Zone class will parse this structure (expecting 'soa' and 'zone' keys)
    }

    /**
     * Exports a zone in BIND/zone file format.
     *
     * @param string $domainName The domain name.
     * @return string|null The plain text zone file content, or null on failure.
     */
    public function exportzone($domainName) {
        $params = ['zone' => $domainName];
        // export_zone_files response: { "metadata": {...}, "data": { "payload": [ { "zone": "domain.com", "text_b64": "..." } ] } }
        // Or sometimes directly: { "payload": [ { "zone": "domain.com", "text_b64": "..." } ] }
        $responseData = $this->callWhmApi('export_zone_files', $params);
        
        $payload = null;
        if (isset($responseData['payload']) && is_array($responseData['payload'])) {
            $payload = $responseData['payload'];
        } elseif (is_array($responseData)) { // If the response IS the payload array
            $payload = $responseData;
        }

        if ($payload) {
            foreach ($payload as $item) {
                if (isset($item['zone']) && $item['zone'] === $domainName && isset($item['text_b64'])) {
                    return base64_decode($item['text_b64']);
                }
            }
        }
        throw new Exception("Could not find zone {$domainName} in export_zone_files response or response format unexpected.");
    }

    /**
     * Deletes a DNS zone.
     *
     * @param string $domainName The domain name to delete.
     * @return array WHM API response.
     */
    public function deletezone($domainName) {
        $params = ['domain' => $domainName];
        return $this->callWhmApi('killdns', $params, 'GET');
    }

    /**
     * Creates a new DNS zone.
     *
     * @param string $domainName The domain name.
     * @param string $ipAddress The primary IP address for the zone's A record.
     * @param string $cpanelUser The cPanel username to own the zone.
     * @param string $template WHM zone template to use (e.g., 'standard').
     * @return array WHM API response from adddns.
     */
    public function createWhmZone($domainName, $ipAddress, $cpanelUser, $template = 'standard') {
        $params = [
            'domain' => $domainName,
            'ip' => $ipAddress,
            'trueowner' => $cpanelUser, // Based on adddns documentation
            'template' => $template
        ];
        return $this->callWhmApi('adddns', $params, 'GET');
    }

    /**
     * Adds a single DNS record to an existing zone.
     *
     * @param string $domainName The zone's domain name.
     * @param array $recordData Associative array of record data (name, type, content, ttl, class, etc.).
     * @return array WHM API response from addzonerecord.
     */
    public function addWhmRecord($domainName, $recordData) {
        $params = [
            'domain' => $domainName, 
            'name' => rtrim($recordData['name'],'.'), // WHM often prefers name without trailing dot for add/edit
            'type' => strtoupper($recordData['type']),
            'ttl' => isset($recordData['ttl']) ? (int)$recordData['ttl'] : 14400,
            'class' => isset($recordData['class']) ? $recordData['class'] : 'IN',
        ];
        $this->mapContentToWhmParams($params, $recordData['type'], $recordData['content']);
        return $this->callWhmApi('addzonerecord', $params, 'GET');
    }

    /**
     * Edits an existing DNS record in a zone.
     *
     * @param string $domainName The zone's domain name.
     * @param int $lineNumber The line number of the record to edit (from dumpzone).
     * @param array $newRecordData Associative array of the new record data.
     * @return array WHM API response from editzonerecord.
     */
    public function editWhmRecord($domainName, $lineNumber, $newRecordData) {
        $params = [
            'domain' => $domainName, 
            'line' => (int)$lineNumber,
            'name' => rtrim($newRecordData['name'],'.'),
            'type' => strtoupper($newRecordData['type']),
            'ttl' => isset($newRecordData['ttl']) ? (int)$newRecordData['ttl'] : 14400,
            'class' => isset($newRecordData['class']) ? $newRecordData['class'] : 'IN',
        ];
        $this->mapContentToWhmParams($params, $newRecordData['type'], $newRecordData['content']);
        return $this->callWhmApi('editzonerecord', $params, 'GET');
    }

    /**
     * Removes a specific DNS record from a zone by its line number.
     *
     * @param string $domainName The zone's domain name.
     * @param int $lineNumber The line number of the record to remove (from dumpzone).
     * @return array WHM API response from removezonerecord.
     */
    public function removeWhmRecord($domainName, $lineNumber) {
        $params = [
            'zone' => $domainName, 
            'line' => (int)$lineNumber,
        ];
        return $this->callWhmApi('removezonerecord', $params, 'GET');
    }

    private function mapContentToWhmParams(&$params, $type, $content) {
        $type = strtoupper($type);
        // Use a local copy or ensure global is accessible
        $whmRecordContentFields = [ 
            'A'     => 'address', 'AAAA'  => 'address', 'CNAME' => 'cname',
            'MX'    => ['preference', 'exchange'], 'TXT'   => 'txtdata',
            'SRV'   => ['priority', 'weight', 'port', 'target'], 'NS'    => 'nsdname',
            'PTR'   => 'ptrdname', 'CAA'   => ['flags', 'tag', 'value'],
        ];

        if (!isset($whmRecordContentFields[$type])) {
            if (is_string($content)) {
                // For TXT-like records (SPF, DKIM often stored as TXT) or unknown types
                // WHM's 'txtdata' is a common field for string content.
                $params['txtdata'] = $content; 
            } elseif (is_array($content) && $type === 'TXT') { // Handle array for TXT if it's split into parts
                 $params['txtdata'] = implode(" ", array_map(function($part) {
                    return '"' . str_replace('"', '\"', $part) . '"';
                 }, $content));
            } else {
                 error_log("WhmApi::mapContentToWhmParams: Unhandled type '{$type}' or non-string content for unknown type.");
            }
            return;
        }

        $whmFields = $whmRecordContentFields[$type];

        if (is_array($whmFields)) { 
            if (!is_array($content)) {
                $contentParts = preg_split('/\s+/', trim((string)$content), count($whmFields));
                if (count($contentParts) === count($whmFields)) {
                    $content = $contentParts;
                } else {
                    throw new Exception("Content for type {$type} is expected to be an array or a parsable string with " . count($whmFields) . " parts. Received: " . print_r($content, true));
                }
            }
            foreach ($whmFields as $index => $fieldName) {
                if (isset($content[$index])) {
                    $params[$fieldName] = $content[$index];
                } else {
                     throw new Exception("Missing content part for field '{$fieldName}' in type {$type}.");
                }
            }
        } else { 
            if ($type === 'TXT' && is_array($content)) { // Handle array for TXT if it's split into parts
                 $params[$whmFields] = implode(" ", array_map(function($part) {
                    return '"' . str_replace('"', '\"', $part) . '"';
                 }, $content));
            } else {
                $params[$whmFields] = $content;
            }
        }
    }
    
    public function savezone(Zone $zoneObject, $cpanelUser, $defaultIpForNewZone = '127.0.0.1') {
        $domainName = $zoneObject->getName(); 
        $desiredRecords = $zoneObject->getRecordsArray(); 

        $liveZoneData = null;
        $isNewZone = false;
        try {
            $liveZoneData = $this->loadzone($domainName); 
        } catch (Exception $e) {
            $errorMessage = strtolower($e->getMessage());
            if (strpos($errorMessage, 'could not find') !== false || 
                strpos($errorMessage, 'does not exist') !== false ||
                strpos($errorMessage, 'no such domain') !== false ||
                (isset($this->apiHandler->last_http_code) && $this->apiHandler->last_http_code == 404) 
            ) {
                $isNewZone = true;
            } else {
                throw $e; 
            }
        }

        if ($isNewZone) {
            $primaryARecordIp = $defaultIpForNewZone;
            foreach ($desiredRecords as $rec) {
                if ( (strtolower($rec['name']) === strtolower($domainName) || strtolower($rec['name']) === strtolower(rtrim($domainName,'.'))) && 
                     strtoupper($rec['type']) === 'A' && 
                     filter_var($rec['content'], FILTER_VALIDATE_IP)) {
                    $primaryARecordIp = $rec['content']; 
                    break;
                }
            }
            $this->createWhmZone($domainName, $primaryARecordIp, $cpanelUser);
            foreach ($desiredRecords as $recordData) {
                if (strtoupper($recordData['type']) === 'SOA') continue; 
                $this->addWhmRecord($domainName, $recordData);
            }
            return ['status' => 'created', 'domain' => $domainName, 'records_processed' => count($desiredRecords)];
        }

        $currentRecordsRaw = isset($liveZoneData['zone']) ? $liveZoneData['zone'] : [];
        $currentRecordsByLine = [];
        foreach ($currentRecordsRaw as $rec) {
            $currentRecordsByLine[$rec['Line']] = $rec;
        }

        $operations = ['added' => 0, 'edited' => 0, 'deleted' => 0, 'unchanged' => 0, 'errors' => []];
        $desiredRecordSignatures = [];
        
        $normalizedDomainName = strtolower(rtrim($domainName,'.'));

        foreach ($desiredRecords as $idx => $desiredRec) {
            // Normalize desired record name for signature creation
            $normalizedDesiredName = strtolower(rtrim($desiredRec['name'],'.'));
            if ($normalizedDesiredName === '@' || $normalizedDesiredName === $normalizedDomainName) {
                $normalizedDesiredName = $normalizedDomainName; // Ensure apex is consistent
            }

            $sig = $normalizedDesiredName . '#' . strtoupper($desiredRec['type']) . '#' . $this->getComparableContent($desiredRec, false);
            $desiredRecordSignatures[$sig] = $desiredRec;
            $desiredRecordSignatures[$sig]['_processed_'] = false;
            $desiredRecordSignatures[$sig]['_original_idx_'] = $idx; // Keep original index if needed
        }
        
        foreach ($currentRecordsByLine as $line => $currentRec) {
            $currentRecNameNormalized = strtolower(rtrim($currentRec['name'],'.'));
            if ($currentRecNameNormalized === '@' || $currentRecNameNormalized === $normalizedDomainName) {
                 $currentRecNameNormalized = $normalizedDomainName;
            }

            if (strtoupper($currentRec['type']) === 'SOA') {
                $soaSig = $currentRecNameNormalized . '#SOA#' . $this->getComparableContent($currentRec, true);
                if (isset($desiredRecordSignatures[$soaSig])) {
                    $desiredRecordSignatures[$soaSig]['_processed_'] = true; 
                    $operations['unchanged']++;
                } else {
                    $operations['unchanged']++; 
                }
                continue;
            }

            $foundInDesired = false;
            foreach ($desiredRecordSignatures as $desiredSig => &$desiredRecEntry) { 
                if ($desiredRecEntry['_processed_']) continue;

                $desiredRecNameNormalized = strtolower(rtrim($desiredRecEntry['name'],'.'));
                 if ($desiredRecNameNormalized === '@' || $desiredRecNameNormalized === $normalizedDomainName) {
                    $desiredRecNameNormalized = $normalizedDomainName;
                }

                if ($currentRecNameNormalized === $desiredRecNameNormalized && strtoupper($currentRec['type']) === strtoupper($desiredRecEntry['type'])) {
                    if ($this->getComparableContent($currentRec, true) === $this->getComparableContent($desiredRecEntry, false) &&
                        (int)$currentRec['ttl'] === (int)$desiredRecEntry['ttl']) {
                        $operations['unchanged']++;
                    } else {
                        try {
                            $this->editWhmRecord($domainName, $line, $desiredRecEntry);
                            $operations['edited']++;
                        } catch (Exception $e) { $operations['errors'][] = "Edit Line {$line} ({$currentRec['name']} {$currentRec['type']}): ".$e->getMessage(); }
                    }
                    $desiredRecEntry['_processed_'] = true;
                    $foundInDesired = true;
                    break;
                }
            }
            unset($desiredRecEntry); 

            if (!$foundInDesired) { 
                try {
                    $this->removeWhmRecord($domainName, $line);
                    $operations['deleted']++;
                } catch (Exception $e) { $operations['errors'][] = "Delete Line {$line} ({$currentRec['name']} {$currentRec['type']}): ".$e->getMessage(); }
            }
        }

        foreach ($desiredRecordSignatures as $sig => $desiredRec) {
            if (!$desiredRec['_processed_']) {
                 if (strtoupper($desiredRec['type']) === 'SOA') continue; 
                try {
                    $this->addWhmRecord($domainName, $desiredRec);
                    $operations['added']++;
                } catch (Exception $e) { $operations['errors'][] = "Add {$desiredRec['name']}/{$desiredRec['type']}: ".$e->getMessage(); }
            }
        }
        
        return ['status' => 'updated', 'domain' => $domainName, 'operations' => $operations];
    }
    
    private function getComparableContent($record, $isWhmFormat = false) {
        $type = strtoupper($record['type']);
        $whmRecordContentFields = [ 
            'A'     => 'address', 'AAAA'  => 'address', 'CNAME' => 'cname',
            'MX'    => ['preference', 'exchange'], 'TXT'   => 'txtdata',
            'SRV'   => ['priority', 'weight', 'port', 'target'], 'NS'    => 'nsdname',
            'PTR'   => 'ptrdname', 'CAA'   => ['flags', 'tag', 'value'],
        ];

        $contentValue = '';
        if ($isWhmFormat) { 
            $fieldsToUse = isset($whmRecordContentFields[$type]) ? $whmRecordContentFields[$type] : null;
            if (is_array($fieldsToUse)) {
                $parts = [];
                foreach ($fieldsToUse as $field) { $parts[] = isset($record[$field]) ? trim($record[$field]) : ''; }
                $contentValue = implode(' ', $parts);
            } elseif ($fieldsToUse && isset($record[$fieldsToUse])) {
                $contentValue = trim((string)$record[$fieldsToUse]);
            } elseif (isset($record['rdata'])) { 
                $contentValue = trim((string)$record['rdata']);
            } elseif (isset($record['data'])) { 
                 $contentValue = is_array($record['data']) ? implode(' ', array_map('trim', $record['data'])) : trim((string)$record['data']);
            }
        } else { 
            $contentValue = is_array($record['content']) ? implode(' ', array_map('trim', $record['content'])) : trim((string)$record['content']);
        }
        // For TXT records, WHM might store without quotes, while input might have them. Normalize by removing.
        if ($type === 'TXT') {
            return trim($contentValue, '"');
        }
        return $contentValue;
    }

    /**
     * Retrieves DNSSEC keys for a zone.
     *
     * @param string $domainName The domain name.
     * @return array List of key information.
     */
    public function getzonekeys($domainName) {
        $keys = [];
        $domainNameClean = rtrim($domainName, '.');

        try {
            $dnskeyDataRaw = $this->callWhmApi('export_zone_dnskey', ['domain' => $domainNameClean]);
            $whmDnskeys = [];

            // The WHM API for export_zone_dnskey might return data directly or nested under 'dnskey' or 'payload'
            if (isset($dnskeyDataRaw['dnskey']) && is_array($dnskeyDataRaw['dnskey'])) {
                 $whmDnskeys = $dnskeyDataRaw['dnskey'];
            } elseif (isset($dnskeyDataRaw[0]['key'])) { // If response is directly the array of keys
                 $whmDnskeys = $dnskeyDataRaw;
            } elseif (isset($dnskeyDataRaw['payload']['dnskey']) && is_array($dnskeyDataRaw['payload']['dnskey'])) { // another possible structure
                 $whmDnskeys = $dnskeyDataRaw['payload']['dnskey'];
            }


            foreach ($whmDnskeys as $idx => $keyInfo) {
                if (!isset($keyInfo['key']) || !isset($keyInfo['flags']) || !isset($keyInfo['algorithm'])) continue;

                $protocol = 3; 
                $dnskey_string = $keyInfo['flags'] . ' ' . $protocol . ' ' . $keyInfo['algorithm'] . ' ' . $keyInfo['key'];
                
                $keytypeDisplay = 'Unknown';
                if (isset($keyInfo['keytype'])) {
                    $keytypeDisplay = strtoupper($keyInfo['keytype']);
                } elseif ($keyInfo['flags'] == 257) {
                    $keytypeDisplay = 'KSK';
                } elseif ($keyInfo['flags'] == 256) {
                    $keytypeDisplay = 'ZSK';
                }
                
                $keys[$idx] = [
                    'id' => $keyInfo['keytag'] ?? ('key_' . $idx), 
                    'keytag' => $keyInfo['keytag'] ?? null,
                    'active' => isset($keyInfo['active']) ? (bool)$keyInfo['active'] : false, 
                    'keytype' => $keytypeDisplay,
                    'algorithm_number' => $keyInfo['algorithm'], // Store algorithm number
                    'algorithm_name' => $this->getDnssecAlgorithmName($keyInfo['algorithm']), // Get friendly name
                    'flags' => $keyInfo['flags'],
                    'dnskey_record_text' => $domainNameClean . '. IN DNSKEY ' . $dnskey_string,
                    'ds_records_text' => [], 
                    'dstxt' => $domainNameClean . '. IN DNSKEY ' . $dnskey_string . "\n", 
                ];
            }
        } catch (Exception $e) {
            error_log("WHM API getzonekeys (export_zone_dnskey) failed for {$domainNameClean}: " . $e->getMessage());
        }

        try {
            $dsDataRaw = $this->callWhmApi('fetch_ds_records_for_domains', ['domain' => $domainNameClean]);
            $whmDsRecords = [];
            
            // DS records might be under 'ds_records', 'payload', or directly an array
            if (isset($dsDataRaw['ds_records']) && is_array($dsDataRaw['ds_records'])) {
                $whmDsRecords = $dsDataRaw['ds_records'];
            } elseif (isset($dsDataRaw['payload']) && is_array($dsDataRaw['payload'])) {
                $whmDsRecords = $dsDataRaw['payload'];
            } elseif (is_array($dsDataRaw) && (isset($dsDataRaw[0]['keytag']) || (isset($dsDataRaw[0]) && is_string($dsDataRaw[0])) ) ) { 
                $whmDsRecords = $dsDataRaw;
            }

            foreach ($whmDsRecords as $dsInfo) {
                $ds_string_parts = [];
                if (is_string($dsInfo)) { 
                    $ds_string_parts = preg_split('/\s+/', $dsInfo, 4); // keytag alg digesttype digest
                } elseif (is_array($dsInfo) && isset($dsInfo['keytag']) && isset($dsInfo['algorithm']) && isset($dsInfo['digest_type']) && isset($dsInfo['digest'])) {
                    $ds_string_parts = [$dsInfo['keytag'], $dsInfo['algorithm'], $dsInfo['digest_type'], strtoupper($dsInfo['digest'])];
                }

                if (count($ds_string_parts) === 4) {
                    $ds_record_text = $domainNameClean . '. IN DS ' . implode(' ', $ds_string_parts);
                    $keytag_from_ds = (int)$ds_string_parts[0];
                    $associated = false;
                    foreach ($keys as $key_idx => &$keyEntry) { 
                        if (isset($keyEntry['keytag']) && (int)$keyEntry['keytag'] === $keytag_from_ds) {
                            $keyEntry['ds_records_text'][] = $ds_record_text;
                            $keyEntry['dstxt'] .= $ds_record_text . "\n";
                            $associated = true;
                            break;
                        }
                    }
                    unset($keyEntry); 
                    if (!$associated) { 
                        $keys[] = [ 
                            'id' => 'ds_' . $keytag_from_ds . '_' . (count($keys)),
                            'active' => true, 
                            'keytype' => 'DS Record (Unmatched)',
                            'algorithm_number' => (int)$ds_string_parts[1],
                            'algorithm_name' => $this->getDnssecAlgorithmName((int)$ds_string_parts[1]),
                            'keytag' => $keytag_from_ds,
                            'dnskey_record_text' => '',
                            'ds_records_text' => [$ds_record_text],
                            'dstxt' => $ds_record_text . "\n",
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            error_log("WHM API getzonekeys (fetch_ds_records_for_domains) failed for {$domainNameClean}: " . $e->getMessage());
        }
        
        foreach ($keys as &$keyEntry) {
            $keyEntry['dstxt'] = trim($keyEntry['dstxt']);
        }
        unset($keyEntry);

        return array_values($keys); 
    }

    /**
     * Parses raw zone file text using WHM's parse_dns_zone API.
     * Decodes base64 fields from the response.
     *
     * @param string $domainName The domain name the zone text belongs to.
     * @param string $zoneFileText The raw zone file content.
     * @return array ['soa' => decoded_soa_data, 'records' => array_of_decoded_records]
     * @throws Exception If API call or parsing fails.
     */
    public function parseZoneFileText($domainName, $zoneFileText) {
        $params = [
            'zone' => rtrim($domainName, '.'), // WHM API often prefers no trailing dot for 'zone' param
            'zonefile_text' => $zoneFileText
        ];
        // parse_dns_zone returns data under 'payload' for records and 'soa' for SOA.
        // Fields like dname_b64, record_type_b64, data_b64 need decoding.
        $responseData = $this->callWhmApi('parse_dns_zone', $params);

        $decodedRecords = [];
        $decodedSoa = null;

        if (isset($responseData['payload']) && is_array($responseData['payload'])) {
            foreach ($responseData['payload'] as $rawRecord) {
                $record = [];
                foreach ($rawRecord as $key => $value) {
                    if (strpos($key, '_b64') !== false) {
                        $newKey = str_replace('_b64', '', $key);
                        if (is_array($value)) { // 'data_b64' can be an array of strings
                            $record[$newKey] = array_map('base64_decode', $value);
                        } else {
                            $record[$newKey] = base64_decode($value);
                        }
                    } else {
                        $record[$key] = $value;
                    }
                }
                // Ensure standard field names like 'name', 'type', 'ttl', 'content'
                if (isset($record['dname'])) $record['name'] = rtrim($record['dname'],'.').'.';
                if (isset($record['record_type'])) $record['type'] = strtoupper($record['record_type']);
                if (isset($record['data'])) { // 'data' is an array of content parts
                    $record['content'] = count($record['data']) === 1 ? $record['data'][0] : $record['data'];
                }
                $decodedRecords[] = $record;
            }
        }

        if (isset($responseData['soa']) && is_array($responseData['soa'])) {
            $decodedSoa = [];
            foreach ($responseData['soa'] as $key => $value) {
                 if (strpos($key, '_b64') !== false) {
                    $newKey = str_replace('_b64', '', $key);
                    $decodedSoa[$newKey] = base64_decode($value);
                } else {
                    $decodedSoa[$key] = $value;
                }
            }
            // Standardize SOA fields
            if (isset($decodedSoa['dname'])) $decodedSoa['name'] = rtrim($decodedSoa['dname'],'.').'.';
            $decodedSoa['type'] = 'SOA';
             // Construct content string for SOA for consistency if needed by Zone class
            $soaContentParts = [];
            foreach (['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'] as $field) {
                $soaContentParts[] = $decodedSoa[$field] ?? '';
            }
            $decodedSoa['content'] = implode(' ', $soaContentParts);

        }
        
        // Ensure SOA is also part of the records list if not already
        if ($decodedSoa) {
            $soaInRecords = false;
            foreach($decodedRecords as $rec) {
                if (isset($rec['type']) && $rec['type'] === 'SOA') {
                    $soaInRecords = true;
                    break;
                }
            }
            if (!$soaInRecords) {
                $soaForList = $decodedSoa;
                // 'line_index' might not be present for SOA from 'soa' part of response
                $soaForList['line_index'] = $decodedSoa['line_index'] ?? 0; // Default to 0 or find
                $decodedRecords[] = $soaForList;
            }
        }


        return ['soa' => $decodedSoa, 'records' => $decodedRecords];
    }
    
    private function getDnssecAlgorithmName($algoNumber) {
        // Based on IANA DNS Security Algorithm Numbers:
        // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
        $algos = [
            1 => "RSA/MD5 (deprecated)", 2 => "Diffie-Hellman (deprecated)", 3 => "DSA/SHA-1 (deprecated)",
            4 => "Elliptic Curve (deprecated)", 5 => "RSA/SHA-1 (deprecated)", 6 => "DSA-NSEC3-SHA1 (deprecated)",
            7 => "RSASHA1-NSEC3-SHA1 (deprecated)", 8 => "RSA/SHA-256", 10 => "RSA/SHA-512",
            12 => "GOST R 34.10-2001 (deprecated)", 13 => "ECDSA/P-256/SHA-256", 14 => "ECDSA/P-384/SHA-384",
            15 => "Ed25519", 16 => "Ed448"
            // Add more as needed
        ];
        return $algos[$algoNumber] ?? "Unknown ({$algoNumber})";
    }

}
?>
```

Next, I'll update the `create` action in `zones.php` (Canvas ID `nsedit_whm_zones_controller`) to use this new `parseZoneFileText` method.


```php
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
    $zoneinfo = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;


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
                
                $is_dnssec_enabled_for_zone = false; // Default
                $key_info_for_zone = [];

                try {
                    $detailedZoneData = $api->loadzone($zone->getName()); 
                    $zone->parseWhmData($detailedZoneData); 
                    
                    // Attempt to fetch DNSSEC keys. WhmApi::getzonekeys might return empty if not enabled or no keys.
                    $key_info_for_zone = $api->getzonekeys($zone->getName());
                    if (!empty($key_info_for_zone)) {
                        // A simple check: if any active keys are returned, consider DNSSEC "active" for display.
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
                    'dnssec' => $zone->isDnssecEnabled(), // From the status we just determined
                    'keyinfo' => $zone->getKeyinfo(),   // The actual key data
                    'masters' => [] 
                ];
                array_push($return, $exportData);
            }
            usort($return, "zone_compare");
            jtable_respond($return);
            break;

        case "getzonekeys": // New action to fetch DNSSEC keys for a specific zone on demand
            $domainName = isset($_GET['zoneid']) ? $_GET['zoneid'] : (isset($_POST['zoneid']) ? $_POST['zoneid'] : null);
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
            jtable_respond($keys); // jTable expects 'Records' key for list, but JS can handle direct array
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
            $rawZoneText = isset($_POST['zone']) ? $_POST['zone'] : null;

            if (!is_adminuser() && $allowzoneadd !== TRUE) {
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
             if (empty($primaryIp) || !filter_var($primaryIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                jtable_respond(null, 'error', "A valid primary IPv4 address is required for new zones.");
                exit;
            }

            $existingOwner = get_zone_account($domainName, '');
            if (!empty($existingOwner) && $existingOwner !== $cpanelUser && !is_adminuser()) {
                 jtable_respond(null, 'error', "Zone {$domainName} is already associated with another account in this system.");
                 exit;
            }

            // Create the basic zone first
            $api->createWhmZone($domainName, $primaryIp, $cpanelUser);
            writelog("Basic zone {$domainName} created for user {$cpanelUser} with IP {$primaryIp}.");

            $zone = new Zone($domainName); // Create Zone object for further operations
            $zone->setCpanelUser($cpanelUser);

            if (!empty($rawZoneText)) {
                writelog("Attempting to import records from provided zone text for {$domainName}.");
                try {
                    $parsedZoneData = $api->parseZoneFileText($domainName, $rawZoneText);
                    if (isset($parsedZoneData['records']) && is_array($parsedZoneData['records'])) {
                        $recordsToAdd = [];
                        foreach ($parsedZoneData['records'] as $parsedRecord) {
                            // Skip SOA from imported text as adddns creates one.
                            // Also, WHM's adddns likely sets up default NS records.
                            // Be cautious about overwriting or duplicating them.
                            // It's safer to skip NS from imported text if 'owns' (overwrite NS) isn't checked/handled.
                            $type = strtoupper($parsedRecord['type'] ?? '');
                            if ($type === 'SOA') continue;
                            
                            // If 'owns' (overwrite nameservers) is not set (or not '1'), skip NS records from import
                            $overwriteNameservers = isset($_POST['owns']) && $_POST['owns'] == '1';
                            if ($type === 'NS' && !$overwriteNameservers) {
                                writelog("Skipping NS record from import for {$domainName} as overwrite not specified.");
                                continue;
                            }

                            // Construct record data for addWhmRecord
                            // Ensure 'content' is in the generic format expected by mapContentToWhmParams
                            $recordData = [
                                'name' => $parsedRecord['name'] ?? $domainName,
                                'type' => $type,
                                'ttl'  => isset($parsedRecord['ttl']) ? (int)$parsedRecord['ttl'] : ($defaults['ttl'] ?? 14400),
                                'class'=> $parsedRecord['class'] ?? 'IN',
                                'content' => $parsedRecord['content'] ?? (isset($parsedRecord['data']) ? (is_array($parsedRecord['data']) ? implode(' ', $parsedRecord['data']) : $parsedRecord['data']) : '')
                            ];
                            $recordsToAdd[] = $recordData;
                        }

                        // Add these records one by one
                        // A batch operation (mass_edit_dns_zone) would be more efficient here
                        foreach ($recordsToAdd as $recordData) {
                            try {
                                $api->addWhmRecord($domainName, $recordData);
                                writelog("Added imported record to {$domainName}: {$recordData['name']} {$recordData['type']}");
                            } catch (Exception $e) {
                                writelog("Error adding imported record {$recordData['name']} {$recordData['type']} to {$domainName}: " . $e->getMessage());
                            }
                        }
                    } else {
                        writelog("No records found or error parsing provided zone text for {$domainName}.");
                    }
                } catch (Exception $e) {
                    writelog("Error processing provided zone text for {$domainName}: " . $e->getMessage());
                    // Continue with template/default records even if import fails
                }
            } else {
                // Add default NS records if provided in config and not importing text (or if 'owns' is true)
                $applyDefaultNS = true;
                if (!empty($rawZoneText) && isset($_POST['owns']) && $_POST['owns'] != '1') {
                    $applyDefaultNS = false; // Don't apply default NS if importing text and not overwriting NS
                }

                if ($applyDefaultNS && isset($defaults['nameservers']) && is_array($defaults['nameservers'])) {
                    foreach ($defaults['nameservers'] as $ns) {
                        $zone->addRecord($domainName, 'NS', $ns, $defaults['ttl'] ?? 14400);
                    }
                }
                // Add default MX record if in config
                 if (isset($defaults['mail_servers']) && is_array($defaults['mail_servers'])) {
                    foreach ($defaults['mail_servers'] as $mx) {
                         $zone->addRecord($domainName, 'MX', (isset($mx['priority']) ? $mx['priority'] . ' ' : '10 ') . $mx['host'], $defaults['ttl'] ?? 14400);
                    }
                }
                // If there are records in the $zone object from defaults, save them
                if (count($zone->getRecordsArray()) > 0) { // getRecordsArray needs to be records added locally
                    $api->savezone($zone, $cpanelUser, $primaryIp); // This savezone will add these records
                }
            }
            
            add_db_zone($zone->getName(), $cpanelUser); 

            // Apply template if selected (after initial zone creation and potential import)
            if (isset($_POST['template']) && $_POST['template'] != 'None' && !empty($templates)) {
                $templateData = null;
                foreach ($templates as $t) {
                    if ($t['name'] === $_POST['template']) {
                        $templateData = $t;
                        break;
                    }
                }
                if ($templateData) {
                    $currentZoneData = $api->loadzone($domainName); // Re-load to get current state after import/defaults
                    $zone->parseWhmData($currentZoneData); 

                    foreach ($templateData['records'] as $recordTpl) {
                        $recordName = str_replace('[ZONENAME]', $zone->getName(), $recordTpl['name']);
                        $recordContent = str_replace('[ZONENAME]', $zone->getName(), $recordTpl['content']);
                        $recordContent = str_replace('[SERVER_IP]', $primaryIp, $recordContent); 
                        
                        // Add to local zone object; savezone will handle API calls
                        $zone->addRecord($recordName, $recordTpl['type'], $recordContent, $recordTpl['ttl'] ?? ($defaults['ttl'] ?? 14400));
                    }
                    $api->savezone($zone, $cpanelUser, $primaryIp); // Save again with template records
                }
            }
            
            $finalZoneData = $api->loadzone($domainName);
            $zone->parseWhmData($finalZoneData);

            writelog("Finished creating zone " . $zone->getName() . " for cPanel user " . $cpanelUser);
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
