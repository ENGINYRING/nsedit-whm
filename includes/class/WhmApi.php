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
        $this->apiHandler->url = $function . '?' . $queryString;

        if ($this->apiHandler->method === 'POST') {
            // For WHM API 1, POST often still sends parameters in URL,
            // but if a body is needed, $this->apiHandler->content would be set.
            // For simplicity here, assuming GET-style params for most common DNS functions.
            // If specific functions require POST body, this might need adjustment or
            // setting $this->apiHandler->content before calling this method.
            // For now, we'll assume parameters are always in the URL for DNS functions.
            $this->apiHandler->content = null; // Ensure no accidental POST body from previous calls
        }

        try {
            $this->apiHandler->call();
            // WHM API typically has data under a 'data' key or directly,
            // and metadata for status.
            if (isset($this->apiHandler->json['metadata']['result']) && $this->apiHandler->json['metadata']['result'] == 1) {
                return isset($this->apiHandler->json['data']) ? $this->apiHandler->json['data'] : $this->apiHandler->json;
            } elseif (isset($this->apiHandler->json['result']) && $this->apiHandler->json['result'] == 1 && isset($this->apiHandler->json['data'])) {
                // Some cPanel API calls (like UAPI via WHM) might have a slightly different structure
                return $this->apiHandler->json['data'];
            } elseif (isset($this->apiHandler->json['status']) && $this->apiHandler->json['status'] == 1 && isset($this->apiHandler->json['payload'])) {
                // Another observed successful structure
                 return $this->apiHandler->json['payload'];
            } elseif (isset($this->apiHandler->json['metadata']['result']) && $this->apiHandler->json['metadata']['result'] == 0) {
                $reason = isset($this->apiHandler->json['metadata']['reason']) ? $this->apiHandler->json['metadata']['reason'] : 'Unknown error';
                throw new Exception("WHM API Error for {$function}: " . $reason);
            }
            // If metadata.result is not present, but http code was 200, it might be a direct data response
            if ($this->apiHandler->last_http_code >= 200 && $this->apiHandler->last_http_code < 300 && isset($this->apiHandler->json)) {
                return $this->apiHandler->json;
            }
            throw new Exception("WHM API call to {$function} failed or returned unexpected structure. HTTP Code: {$this->apiHandler->last_http_code}");
        } catch (Exception $e) {
            // Log the error or handle it more gracefully if needed
            // error_log("WhmApi Error: " . $e->getMessage());
            throw $e; // Re-throw the exception
        }
    }

    /**
     * Lists DNS zones.
     * Note: WHM's `listzones` is basic. `listaccts` provides more user context.
     * This implementation will try to provide a richer output similar to the old PdnsApi,
     * which might involve multiple calls per domain if full details are needed immediately.
     * For performance, consider lazy loading details in the Zone object or zones.php.
     *
     * @param string|false $searchQuery Optional search query for domain names.
     * @return array List of zone data arrays.
     */
    public function listzones($searchQuery = false) {
        $zones = array();
        $params = array();

        // Using listaccts as it's more commonly used and can be searched
        // and provides user information.
        $apiFunction = 'listaccts';
        if ($searchQuery) {
            $params['search'] = $searchQuery;
            $params['searchtype'] = 'domain'; // Search by domain name
        }

        $responseData = $this->callWhmApi($apiFunction, $params);

        if (isset($responseData['acct']) && is_array($responseData['acct'])) {
            foreach ($responseData['acct'] as $account) {
                if (empty($account['domain'])) continue;

                // Basic info from listaccts
                $zoneData = [
                    'id' => $account['domain'], // Use domain name as ID
                    'name' => $account['domain'],
                    'account' => $account['user'], // cPanel username
                    'kind' => 'Master', // WHM generally manages master zones locally
                    'url' => null, // Not applicable for WHM in the same way as PowerDNS
                    'serial' => null, // Needs dumpzone
                    'dnssec' => false, // Needs separate DNSSEC check
                    'masters' => [], // Not directly applicable unless parsing specific NS for slave-like setup
                ];
                $zones[] = $zoneData;
            }
        } else if (isset($responseData['zone']) && is_array($responseData['zone'])) {
            // Fallback or alternative if listzones WHM API was used and has this structure
            foreach ($responseData['zone'] as $zoneInfo) {
                 if (empty($zoneInfo['domain'])) continue;
                 $zones[] = [
                    'id' => $zoneInfo['domain'],
                    'name' => $zoneInfo['domain'],
                    'account' => null, // listzones doesn't provide this
                    'kind' => 'Master',
                    'url' => null,
                    'serial' => null,
                    'dnssec' => false,
                    'masters' => [],
                 ];
            }
        }
        // To get 'serial' or 'dnssec' status here, you would need to loop through $zones
        // and call loadZone (dumpzone) and a DNSSEC checking function for each.
        // This can be very slow for many zones. It's better handled by Zone.php or when a zone is selected.
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
        $responseData = $this->callWhmApi('dumpzone', $params);

        // The response from dumpzone is typically:
        // $responseData['data']['zone'] = array of record objects
        // $responseData['data']['soa'] = soa object
        // We need to return this in a format that Zone.php can parse.
        // For now, returning the 'data' part which contains 'zone' and 'soa'.
        return $responseData; // The Zone class will need to parse this structure
    }

    /**
     * Exports a zone in BIND/zone file format.
     *
     * @param string $domainName The domain name.
     * @return string|null The plain text zone file content, or null on failure.
     */
    public function exportzone($domainName) {
        $params = ['zone' => $domainName]; // WHM's export_zone_files uses 'zone'
        $responseData = $this->callWhmApi('export_zone_files', $params);

        // Response structure: $responseData['payload'] is an array.
        // Each item has 'zone' and 'text_b64'.
        if (isset($responseData) && is_array($responseData)) {
            foreach ($responseData as $item) {
                if (isset($item['zone']) && $item['zone'] === $domainName && isset($item['text_b64'])) {
                    return base64_decode($item['text_b64']);
                }
            }
        }
        throw new Exception("Could not find zone {$domainName} in export_zone_files response.");
    }

    /**
     * Deletes a DNS zone.
     *
     * @param string $domainName The domain name to delete.
     * @return array WHM API response.
     */
    public function deletezone($domainName) {
        $params = ['domain' => $domainName];
        return $this->callWhmApi('killdns', $params, 'GET'); // killdns is usually GET
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
            'user' => $cpanelUser, // 'user' is often the parameter for cPanel username in adddns context
                                  // though official docs might say 'trueowner' for some API versions/calls
            'template' => $template
        ];
        // The 'adddns' function might use 'user' or 'trueowner'. Check specific WHM version docs.
        // Let's try 'user' as it's common in createacct contexts which often create DNS.
        // If 'user' fails, 'trueowner' might be the alternative.
        // For WHM API 1 'adddns', 'domain' and 'ip' are primary. 'user'/'trueowner' might be implicit or optional.
        // The documentation for adddns (cPanel API 2 via WHM) shows 'domain', 'ip', 'trueowner'.
        // Let's use 'trueowner' for wider compatibility based on the specific adddns doc.
        unset($params['user']);
        $params['trueowner'] = $cpanelUser;

        return $this->callWhmApi('adddns', $params, 'GET'); // adddns is often GET
    }

    /**
     * Adds a single DNS record to an existing zone.
     *
     * @param string $domainName The zone's domain name.
     * @param array $recordData Associative array of record data (name, type, content, ttl, class, etc.).
     * 'content' is generic; this method maps it to WHM fields.
     * @return array WHM API response from addzonerecord.
     */
    public function addWhmRecord($domainName, $recordData) {
        $params = [
            'domain' => $domainName, // 'domain' for addzonerecord, not 'zone'
            'name' => $recordData['name'],
            'type' => strtoupper($recordData['type']),
            'ttl' => isset($recordData['ttl']) ? (int)$recordData['ttl'] : 14400, // Default TTL
            'class' => isset($recordData['class']) ? $recordData['class'] : 'IN',
        ];

        $this->mapContentToWhmParams($params, $recordData['type'], $recordData['content']);
        
        return $this->callWhmApi('addzonerecord', $params, 'GET'); // addzonerecord is often GET
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
            'domain' => $domainName, // 'domain' for editzonerecord
            'line' => (int)$lineNumber,
            'name' => $newRecordData['name'],
            'type' => strtoupper($newRecordData['type']),
            'ttl' => isset($newRecordData['ttl']) ? (int)$newRecordData['ttl'] : 14400,
            'class' => isset($newRecordData['class']) ? $newRecordData['class'] : 'IN',
        ];

        $this->mapContentToWhmParams($params, $newRecordData['type'], $newRecordData['content']);

        return $this->callWhmApi('editzonerecord', $params, 'GET'); // editzonerecord is often GET
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
            'zone' => $domainName, // removezonerecord uses 'zone'
            'line' => (int)$lineNumber,
        ];
        return $this->callWhmApi('removezonerecord', $params, 'GET'); // removezonerecord is often GET
    }


    /**
     * Helper function to map generic 'content' to WHM API's type-specific parameters.
     *
     * @param array &$params The parameter array to be modified.
     * @param string $type The record type (A, MX, TXT, etc.).
     * @param mixed $content The generic content value.
     */
    private function mapContentToWhmParams(&$params, $type, $content) {
        $type = strtoupper($type);
        if (!isset($this->whmRecordContentFields[$type])) {
            // For unknown types, pass content as 'data' or a common field if possible,
            // or let it fail if WHM requires specific fields.
            // This might need adjustment based on how WHM handles less common types.
            // A simple approach for now:
            if (is_string($content)) {
                 // Try common fields, or this could be an error condition
                 // For now, let's assume 'txtdata' might be a fallback for string content
                 // or 'address' if it looks like an IP. This is heuristic.
                if (filter_var($content, FILTER_VALIDATE_IP)) {
                    $params['address'] = $content;
                } else {
                    $params['txtdata'] = $content; // Fallback, might not be correct for all types
                }
            }
            return;
        }

        $whmFields = $this->whmRecordContentFields[$type];

        if (is_array($whmFields)) { // For records with multiple content parts like MX, SRV
            if (!is_array($content) || count($content) < count($whmFields)) {
                 // If content is a string for a multi-part record, try to parse it (e.g. "10 mail.example.com")
                if (is_string($content)) {
                    $contentParts = preg_split('/\s+/', $content, count($whmFields));
                     if (count($contentParts) === count($whmFields)) {
                        $content = $contentParts;
                    } else {
                        throw new Exception("Content for type {$type} is expected to be an array or a parsable string with " . count($whmFields) . " parts.");
                    }
                } else {
                    throw new Exception("Content for type {$type} is expected to be an array with " . count($whmFields) . " elements.");
                }
            }
            foreach ($whmFields as $index => $fieldName) {
                $params[$fieldName] = $content[$index];
            }
        } else { // For records with a single content part like A, TXT, CNAME
            $params[$whmFields] = $content;
        }
    }
    
    /**
     * Saves a zone. This is a complex operation that determines if the zone is new
     * or existing and applies changes accordingly.
     * This version will use individual record operations for simplicity.
     * A more optimized version could use mass_edit_dns_zone.
     *
     * @param Zone $zoneObject An instance of your (modified) Zone class.
     * @param string $cpanelUser The cPanel username, required for creating new zones.
     * @param string $defaultIpForNewZone The default IP for new A record if not found in SOA.
     * @return array Result of the operation.
     */
    public function savezone(Zone $zoneObject, $cpanelUser, $defaultIpForNewZone = '127.0.0.1') {
        $domainName = $zoneObject->getName(); // Assuming Zone class has getName()
        $desiredRecords = $zoneObject->getRecordsArray(); // Assuming Zone class can provide this

        $liveZoneData = null;
        try {
            $liveZoneData = $this->loadzone($domainName); // dumpzone
        } catch (Exception $e) {
            // Zone likely doesn't exist if loadzone fails (e.g., 404 or specific WHM error)
            // Check specific error message or code if possible
            if (strpos(strtolower($e->getMessage()), 'could not find') !== false || strpos(strtolower($e->getMessage()), 'does not exist') !== false) {
                // Zone does not exist, create it
                $primaryARecordIp = $defaultIpForNewZone;
                // Try to find an A record for the apex in the desired state to use as primary IP
                foreach ($desiredRecords as $rec) {
                    if (($rec['name'] === $domainName || $rec['name'] === '@' || $rec['name'] === $domainName . '.') && strtoupper($rec['type']) === 'A') {
                        $primaryARecordIp = $rec['content']; // Assuming content is the IP for A record
                        break;
                    }
                }

                $this->createWhmZone($domainName, $primaryARecordIp, $cpanelUser);
                // After creation, all desired records need to be added
                foreach ($desiredRecords as $recordData) {
                    // WHM's adddns might create some defaults (SOA, NS).
                    // A robust solution would check if a similar record exists from adddns before adding.
                    // For simplicity now, we add all desired records. Duplicates might error or be ignored by WHM.
                    $this->addWhmRecord($domainName, $recordData);
                }
                return ['status' => 'created', 'domain' => $domainName, 'records_processed' => count($desiredRecords)];
            } else {
                throw $e; // Re-throw other errors
            }
        }

        // Zone exists, now sync records (complex part)
        // This requires a diff between $desiredRecords and records from $liveZoneData['zone']
        // and then calls to addWhmRecord, editWhmRecord, removeWhmRecord.

        $currentRecordsRaw = isset($liveZoneData['zone']) ? $liveZoneData['zone'] : [];
        $currentRecords = [];
        foreach ($currentRecordsRaw as $rec) {
            $key = $rec['Line']; // Use line number as a unique key for existing records
            $currentRecords[$key] = $rec;
        }

        $operations = ['added' => 0, 'edited' => 0, 'deleted' => 0, 'unchanged' => 0];
        $processedDesiredRecords = []; // Keep track of desired records that match an existing one

        // Pass 1: Identify records to edit or that are unchanged
        foreach ($desiredRecords as $desiredIdx => $desiredRec) {
            $foundMatch = false;
            foreach ($currentRecords as $line => $currentRec) {
                // Attempt to match desired record with a current record
                // Matching can be tricky: by name+type primarily. Content for exact match.
                // For simplicity, if name & type match, consider it for edit/unchanged.
                // A more robust match would also consider content for identifying *which* record of same name/type to edit.
                if (strtolower(trim($currentRec['name'], '.')) === strtolower(trim($desiredRec['name'], '.')) &&
                    strtoupper($currentRec['type']) === strtoupper($desiredRec['type'])) {
                    
                    // This is a simplification. If multiple records of same name/type exist,
                    // this might pick the first one. A better diff would be needed.
                    // Let's assume for now we try to edit if content differs, else it's unchanged.
                    
                    $currentContentComparable = $this->getComparableContent($currentRec);
                    $desiredContentComparable = $this->getComparableContent($desiredRec);

                    if ($currentContentComparable !== $desiredContentComparable ||
                        (isset($desiredRec['ttl']) && (int)$currentRec['ttl'] !== (int)$desiredRec['ttl'])) {
                        
                        $this->editWhmRecord($domainName, $currentRec['Line'], $desiredRec);
                        $operations['edited']++;
                    } else {
                        $operations['unchanged']++;
                    }
                    $processedDesiredRecords[$desiredIdx] = true;
                    unset($currentRecords[$line]); // Remove from current records as it's been handled
                    $foundMatch = true;
                    break; // Found a match for this desired record
                }
            }
            if (!$foundMatch) {
                // This desired record is new, will be added in Pass 2
            }
        }

        // Pass 2: Add new desired records (those not matched in Pass 1)
        foreach ($desiredRecords as $desiredIdx => $desiredRec) {
            if (!isset($processedDesiredRecords[$desiredIdx])) {
                $this->addWhmRecord($domainName, $desiredRec);
                $operations['added']++;
            }
        }

        // Pass 3: Delete any remaining current records (those not matched/kept in Pass 1)
        foreach ($currentRecords as $line => $currentRec) {
            // Skip SOA and potentially primary NS records if your logic requires them to persist
            // or be managed differently. For now, deleting all unmatchedd records.
            if (strtoupper($currentRec['type']) === 'SOA') continue; 
            
            $this->removeWhmRecord($domainName, $line);
            $operations['deleted']++;
        }
        
        return ['status' => 'updated', 'domain' => $domainName, 'operations' => $operations];
    }

    /**
     * Helper to get comparable content from a record array.
     * This needs to align with how mapContentToWhmParams structures data.
     */
    private function getComparableContent($record) {
        $type = strtoupper($record['type']);
        $whmFields = isset($this->whmRecordContentFields[$type]) ? $this->whmRecordContentFields[$type] : null;

        if (is_array($whmFields)) {
            $contentParts = [];
            foreach ($whmFields as $field) {
                $contentParts[] = isset($record[$field]) ? $record[$field] : '';
            }
            return implode(' ', $contentParts);
        } elseif ($whmFields) {
            return isset($record[$whmFields]) ? $record[$whmFields] : '';
        }
        // Fallback for unknown types or if content is in a generic field
        if (isset($record['rdata'])) return $record['rdata']; // common in some API outputs
        if (isset($record['data'])) return is_array($record['data']) ? implode(' ', $record['data']) : $record['data'];
        if (isset($record['address'])) return $record['address'];
        if (isset($record['txtdata'])) return $record['txtdata'];
        if (isset($record['cname'])) return $record['cname'];
        return json_encode($record); // Worst case, compare full record if no specific content field found
    }


    /**
     * Retrieves DNSSEC keys for a zone.
     * This is a placeholder and needs actual WHM API function for DNSSEC.
     *
     * @param string $domainName The domain name.
     * @return array List of key information.
     */
    public function getzonekeys($domainName) {
        // WHM API for DNSSEC: fetch_ds_records_for_domains or export_zone_dnskey
        // Example using fetch_ds_records_for_domains (hypothetical structure)
        $params = ['domain' => $domainName];
        try {
            // Note: 'fetch_ds_records_for_domains' might be the wrong function or might
            // only return DS records, not the full DNSKEY and KSK/ZSK details.
            // You might need 'export_zone_dnskey' or a combination.
            // This part requires more specific knowledge of WHM's DNSSEC API output.
            $responseData = $this->callWhmApi('fetch_ds_records_for_domains', $params);
            
            $keys = [];
            if (isset($responseData['records']) && is_array($responseData['records'])) {
                foreach ($responseData['records'] as $keyData) {
                    // Adapt this parsing based on actual WHM API response for DNSSEC keys
                    $key = [
                        'id' => isset($keyData['keytag']) ? $keyData['keytag'] : rand(),
                        'active' => isset($keyData['active']) ? (bool)$keyData['active'] : true, // Guess
                        'keytype' => isset($keyData['algorithm_name']) ? $keyData['algorithm_name'] : 'Unknown', // Guess
                        'dnskey' => isset($keyData['dnskey_record_text']) ? $keyData['dnskey_record_text'] : '', // Guess
                        'dstxt' => '',
                    ];
                    if (!empty($key['dnskey'])) {
                         $key['dstxt'] = $domainName . '. IN DNSKEY ' . $key['dnskey'] . "\n";
                    }
                    if (isset($keyData['ds_records']) && is_array($keyData['ds_records'])) {
                        foreach($keyData['ds_records'] as $ds) {
                            $key['dstxt'] .= $domainName . '. IN DS ' . $ds . "\n";
                        }
                    }
                    $keys[] = $key;
                }
            }
            return $keys;

        } catch (Exception $e) {
            // If the function doesn't exist or fails, return empty array or handle error
            error_log("WHM API getzonekeys failed for {$domainName}: " . $e->getMessage());
            return [];
        }
    }
}
?>
