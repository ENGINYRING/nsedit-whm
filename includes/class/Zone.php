<?php

class Zone {
    // Core Zone Properties
    private $domainName; // The actual domain name, e.g., "example.com."
    private $cpanelUser; // cPanel user associated with the zone (if known)
    
    // Records and SOA
    private $records = []; // Array of individual record objects/arrays from WHM dumpzone
    private $soaData = null; // Parsed SOA record data

    // Raw data from WHM API (optional, for reference or advanced use)
    private $rawWhmData = null; 

    // DNSSEC related properties
    private $dnssecEnabled = false; // Placeholder, actual status needs to be fetched
    private $dnssecKeys = [];   // Placeholder for DNSSEC key info

    // For tracking changes if not using a full diff in WhmApi::savezone
    private $pendingChanges = [
        'add' => [],
        'edit' => [], // Stores {line_number, new_data}
        'delete' => [] // Stores {line_number} or record details to find line
    ];


    public function __construct($domainName = '') {
        if (!empty($domainName)) {
            $this->setName($domainName);
        }
        // Initialize other properties
        $this->records = [];
        $this->soaData = null;
        $this->cpanelUser = '';
    }

    /**
     * Parses the data returned by WhmApi::loadzone() (which is from WHM's dumpzone).
     * The expected $whmData structure is an associative array which might contain:
     * $whmData['zone'] = array of record objects
     * $whmData['soa']  = array representing the SOA record
     *
     * @param array $whmData Data from WHM's dumpzone.
     */
    public function parseWhmData($whmData) {
        $this->rawWhmData = $whmData;
        $this->records = []; // Reset records

        if (isset($whmData['zone']) && is_array($whmData['zone'])) {
            foreach ($whmData['zone'] as $whmRecord) {
                // Store the record as is, or transform it slightly if needed for consistency
                // Ensure 'Line' is available if not directly named that (e.g. 'line')
                if (isset($whmRecord['line']) && !isset($whmRecord['Line'])) {
                    $whmRecord['Line'] = $whmRecord['line'];
                }
                $this->records[] = $whmRecord;

                if (strtoupper($whmRecord['type']) === 'SOA') {
                    $this->soaData = $whmRecord; // Store the SOA record separately if needed
                }
            }
        } elseif (is_array($whmData) && !isset($whmData['zone']) && !isset($whmData['soa'])) {
            // If $whmData is directly an array of records (less common for dumpzone but possible)
             foreach ($whmData as $whmRecord) {
                if (isset($whmRecord['line']) && !isset($whmRecord['Line'])) {
                    $whmRecord['Line'] = $whmRecord['line'];
                }
                $this->records[] = $whmRecord;
                if (strtoupper($whmRecord['type']) === 'SOA') {
                    $this->soaData = $whmRecord;
                }
            }
        }


        // If SOA is provided separately by dumpzone structure
        if (isset($whmData['soa']) && is_array($whmData['soa'])) {
            $this->soaData = $whmData['soa'];
            // Ensure SOA is also in the main records list if not already
            $soaFoundInRecords = false;
            foreach ($this->records as $rec) {
                if (strtoupper($rec['type']) === 'SOA') {
                    $soaFoundInRecords = true;
                    break;
                }
            }
            if (!$soaFoundInRecords) {
                 // Add/Update SOA in records list, ensuring it has a 'Line' if possible
                 // Line number for SOA from dumpzone's 'soa' part might not be present,
                 // it's usually the first record in the 'zone' array.
                $soaToAdd = $this->soaData;
                if (!isset($soaToAdd['Line']) && isset($this->records[0]) && strtoupper($this->records[0]['type']) === 'SOA') {
                    $soaToAdd['Line'] = $this->records[0]['Line'];
                } elseif(!isset($soaToAdd['Line'])) {
                    // Try to find it if records are not empty
                    foreach($this->records as $r) {
                        if(strtoupper($r['type']) === 'SOA') {
                            $soaToAdd['Line'] = $r['Line'];
                            break;
                        }
                    }
                }
                if ($soaFoundInRecords) { // Update existing SOA in records
                    foreach($this->records as $idx => $rec) {
                        if (strtoupper($rec['type']) === 'SOA') {
                            $this->records[$idx] = array_merge($rec, $soaToAdd);
                            break;
                        }
                    }
                } else { // Add SOA to records if not found
                    $this->records[] = $soaToAdd;
                }
            }
        }
        
        // Ensure domain name is set if not already
        if (empty($this->domainName) && $this->soaData && isset($this->soaData['name'])) {
            $this->setName($this->soaData['name']);
        }
    }
    
    /**
     * Imports records from a user-supplied plain text zone file.
     * This would typically be used in conjunction with WhmApi::parse_dns_zone.
     * For now, this method will expect already parsed data (e.g. from WhmApi::parse_dns_zone
     * followed by base64 decoding of fields by the caller).
     *
     * @param array $parsedRecords Array of record data hashes.
     * @param array $parsedSoaData Parsed SOA data.
     */
    public function importParsedRecords($parsedRecords, $parsedSoaData = null) {
        $this->records = [];
        foreach ($parsedRecords as $record) {
            // Ensure record has a common structure, e.g. name, type, content, ttl
            // The 'content' here is the generic content, not WHM specific fields yet.
            $this->records[] = [
                'name' => isset($record['dname']) ? rtrim($record['dname'], '.') : (isset($record['name']) ? rtrim($record['name'],'.') : ''),
                'type' => isset($record['record_type']) ? strtoupper($record['record_type']) : (isset($record['type']) ? strtoupper($record['type']) : ''),
                'ttl' => isset($record['ttl']) ? (int)$record['ttl'] : 14400,
                'class' => isset($record['class']) ? $record['class'] : 'IN', // Default class
                // 'content' needs to be structured based on type for WhmApi methods
                // This method assumes $record['data'] or $record['content'] holds the value(s)
                'data_fields' => isset($record['data']) ? $record['data'] : (isset($record['content']) ? $record['content'] : null)
                // Line numbers won't exist for imported text
            ];
        }
        if ($parsedSoaData) {
            $this->soaData = $parsedSoaData;
             if (empty($this->domainName) && isset($parsedSoaData['mname'])) { // mname is often the zone name in SOA
                $this->setName($parsedSoaData['mname']);
            }
        }
         // Ensure records are sorted in a somewhat standard way (SOA, NS, MX, then others)
        $this->sortRecords();
    }


    // --- Getters ---
    public function getName() {
        return rtrim($this->domainName, '.'); // Return without trailing dot for consistency
    }

    public function getDomainNameWithTrailingDot() {
        return rtrim($this->domainName, '.') . '.';
    }

    public function getCpanelUser() {
        return $this->cpanelUser;
    }

    public function getSoaData() {
        return $this->soaData;
    }
    
    public function getSoaSerial() {
        if ($this->soaData && isset($this->soaData['serial'])) {
            return $this->soaData['serial'];
        }
        // Fallback: try to find SOA in records array if not in soaData property
        foreach ($this->records as $record) {
            if (strtoupper($record['type']) === 'SOA' && isset($record['serial'])) {
                return $record['serial'];
            }
        }
        return null;
    }

    public function getRawWhmData() {
        return $this->rawWhmData;
    }

    public function isDnssecEnabled() {
        return $this->dnssecEnabled; // Placeholder
    }

    public function getKeyinfo() {
        return $this->dnssecKeys; // Placeholder
    }

    // --- Setters ---
    public function setName($name) {
        $this->domainName = rtrim($name, '.') . '.'; // Ensure trailing dot internally
    }

    public function setCpanelUser($username) {
        $this->cpanelUser = $username;
    }
    
    public function setDnssec($status) {
        $this->dnssecEnabled = (bool)$status;
    }

    public function setKeyinfo($keyInfoArray) {
        $this->dnssecKeys = $keyInfoArray;
    }

    /**
     * Adds a record to the internal list of desired records.
     * This record will be processed by WhmApi::savezone().
     *
     * @param string $name Record name.
     * @param string $type Record type.
     * @param mixed $content Record content (string or array for MX/SRV).
     * @param int $ttl TTL.
     * @param string $class Record class (default IN).
     * @return array The added record structure.
     */
    public function addRecord($name, $type, $content, $ttl = 14400, $class = 'IN') {
        // Normalize name: ensure it's relative to zone or absolute with trailing dot.
        // If name doesn't end with domainName and doesn't end with '.', append domainName.
        $name = rtrim($name, '.');
        if ($name !== '@' && $name !== $this->getName() && strpos($name, $this->getName()) === false) {
            if (!empty($name)) {
                 $name = $name . '.' . $this->getName();
            } else { // For apex records
                $name = $this->getName();
            }
        }
        $name = rtrim($name, '.') . '.';


        $newRecord = [
            'name' => $name,
            'type' => strtoupper($type),
            'content' => $content, // This is the generic content
            'ttl' => (int)$ttl,
            'class' => $class,
            // 'Line' will not be present for newly added records until after save & reload
        ];
        
        // For WhmApi::savezone diffing, we just add to the desired state.
        // The actual addition to WHM happens via API calls.
        $this->records[] = $newRecord; 
        $this->sortRecords(); // Keep records sorted for consistent diffing/display
        
        return $newRecord; // Return the structure that was added locally
    }

    /**
     * Deletes a record from the internal list based on its details.
     * The actual deletion on the server happens via WhmApi::savezone() or direct removeWhmRecord().
     * This method marks a record for deletion or removes it from the desired state.
     *
     * @param string $name Record name.
     * @param string $type Record type.
     * @param mixed $content Record content to match.
     * @return bool True if a record was found and removed from the local list, false otherwise.
     */
    public function deleteRecord($name, $type, $content) {
        $name = rtrim($name, '.') . '.';
        $type = strtoupper($type);
        $found = false;
        foreach ($this->records as $index => $record) {
            if (rtrim($record['name'],'.').'.' === $name &&
                strtoupper($record['type']) === $type &&
                $this->compareRecordContent($record, $content)) { // compareRecordContent needs to be robust
                unset($this->records[$index]);
                $found = true;
                // If using $pendingChanges for a more granular save:
                // if(isset($record['Line'])) { $this->pendingChanges['delete'][] = ['line' => $record['Line']]; }
                // else { /* This record was only locally added, just remove it */ }
                break; 
            }
        }
        $this->records = array_values($this->records); // Re-index
        return $found;
    }
    
    /**
     * Helper to compare content of a record from WHM (which has specific fields)
     * with a generic content value (string or array).
     */
    private function compareRecordContent($whmApiRecord, $genericContentToCompare) {
        global $whmRecordContentFields; // from WhmApi.php or define locally

        $type = strtoupper($whmApiRecord['type']);
        $fieldsToUse = isset($whmRecordContentFields[$type]) ? $whmRecordContentFields[$type] : null;

        if (is_array($fieldsToUse)) { // MX, SRV
            $currentParts = [];
            foreach ($fieldsToUse as $field) {
                $currentParts[] = isset($whmApiRecord[$field]) ? $whmApiRecord[$field] : '';
            }
            $currentValue = implode(' ', $currentParts);
            
            $compareToValue = is_array($genericContentToCompare) ? implode(' ', $genericContentToCompare) : (string)$genericContentToCompare;
            return strtolower($currentValue) === strtolower($compareToValue);

        } elseif ($fieldsToUse) { // A, TXT, CNAME etc.
            $currentValue = isset($whmApiRecord[$fieldsToUse]) ? $whmApiRecord[$fieldsToUse] : '';
             // For TXT records, WHM often stores them without surrounding quotes in dumpzone.
             // The genericContentToCompare might have come from user input (unquoted) or from
             // a previous system that did quote them.
            if ($type === 'TXT') {
                return trim((string)$genericContentToCompare, '"') === trim((string)$currentValue, '"');
            }
            return strtolower((string)$currentValue) === strtolower((string)$genericContentToCompare);
        }
        // Fallback for unknown types: try to compare 'rdata' or 'data' if present
        if (isset($whmApiRecord['rdata'])) {
            return strtolower((string)$whmApiRecord['rdata']) === strtolower((string)$genericContentToCompare);
        }
        if (isset($whmApiRecord['data'])) {
             $currentData = is_array($whmApiRecord['data']) ? implode(' ',$whmApiRecord['data']) : $whmApiRecord['data'];
             $compareToData = is_array($genericContentToCompare) ? implode(' ', $genericContentToCompare) : $genericContentToCompare;
             return strtolower((string)$currentData) === strtolower((string)$compareToData);
        }
        return false; // Cannot compare
    }


    /**
     * Retrieves a specific record by its details.
     *
     * @param string $name Record name.
     * @param string $type Record type.
     * @param mixed $content Record content to match.
     * @return array|null The found record array or null.
     */
    public function getRecord($name, $type, $content) {
        $name = rtrim($name, '.') . '.';
        $type = strtoupper($type);
        foreach ($this->records as $record) {
            if (rtrim($record['name'],'.').'.' === $name &&
                strtoupper($record['type']) === $type &&
                $this->compareRecordContent($record, $content)) {
                return $this->formatRecordForApp($record); // Format for jTable id etc.
            }
        }
        return null;
    }
    
    /**
     * Formats a WHM record for application use (e.g., jTable).
     * Creates a unique ID string for jTable.
     * Extracts generic 'content'.
     */
    private function formatRecordForApp($whmRecord) {
        $appRecord = $whmRecord; // Start with all fields from WHM

        // Create a generic 'content' field
        $type = strtoupper($whmRecord['type']);
        global $whmRecordContentFields; // Defined in WhmApi.php or should be accessible
        $contentFields = isset($whmRecordContentFields[$type]) ? $whmRecordContentFields[$type] : null;
        
        $contentValue = '';
        if (is_array($contentFields)) {
            $parts = [];
            foreach($contentFields as $field) {
                $parts[] = isset($whmRecord[$field]) ? $whmRecord[$field] : '';
            }
            $contentValue = implode(' ', $parts);
        } elseif ($contentFields && isset($whmRecord[$contentFields])) {
            $contentValue = $whmRecord[$contentFields];
        } elseif (isset($whmRecord['rdata'])) { // Fallback
            $contentValue = $whmRecord['rdata'];
        } elseif (isset($whmRecord['data'])) { // Another fallback
             $contentValue = is_array($whmRecord['data']) ? implode(' ', $whmRecord['data']) : $whmRecord['data'];
        }
        $appRecord['content'] = $contentValue;

        // Create a unique ID for jTable (based on name, type, original content, and line if available)
        // This helps identify the exact record for edits/deletes before it's modified locally.
        $idData = [
            'name' => $whmRecord['name'],
            'type' => $whmRecord['type'],
            'content_orig_whm' => $contentValue, // Store the content as derived from WHM fields
            'ttl' => $whmRecord['ttl'],
            'Line' => isset($whmRecord['Line']) ? $whmRecord['Line'] : null // Include Line if present
        ];
        $appRecord['id'] = json_encode($idData);
        
        // WHM's dumpzone usually doesn't have a 'disabled' field.
        // Comments (lines starting with ';') are used for disabling.
        // If a record from dumpzone starts with ';', it's effectively disabled.
        // This logic might be better handled during parsing if WHM provides raw line.
        // For now, assume records from dumpzone are active unless explicitly commented out in the file.
        $appRecord['disabled'] = (isset($whmRecord['commented_out']) && $whmRecord['commented_out']);


        return $appRecord;
    }

    /**
     * Returns all records, formatted for application use (e.g., jTable).
     *
     * @return array
     */
    public function getRecordsForDisplay() {
        $displayRecords = [];
        foreach ($this->records as $record) {
            $displayRecords[] = $this->formatRecordForApp($record);
        }
        return $displayRecords;
    }
    
    /**
     * Returns the current state of records in a simple array format
     * suitable for the WhmApi::savezone() method's diffing logic.
     * Each record is an array with 'name', 'type', 'content', 'ttl'.
     *
     * @return array
     */
    public function getRecordsArray() {
        $outputRecords = [];
        foreach ($this->records as $internalRec) {
            // $internalRec already holds 'name', 'type', 'ttl'
            // 'content' in $internalRec is the generic content
            $outputRecords[] = [
                'name' => $internalRec['name'],
                'type' => $internalRec['type'],
                'ttl'  => $internalRec['ttl'],
                'content' => $internalRec['content'], // This should be the generic content
                'class' => isset($internalRec['class']) ? $internalRec['class'] : 'IN',
                // Include Line if it exists, for existing records being potentially edited
                'Line' => isset($internalRec['Line']) ? $internalRec['Line'] : null,
            ];
        }
        return $outputRecords;
    }
    
    /**
     * Sorts records: SOA first, then NS, then MX, then by name, then by type.
     */
    public function sortRecords() {
        usort($this->records, function ($a, $b) {
            $typeOrder = ['SOA' => 0, 'NS' => 1, 'MX' => 2];
            $typeA = strtoupper($a['type']);
            $typeB = strtoupper($b['type']);

            $orderA = isset($typeOrder[$typeA]) ? $typeOrder[$typeA] : 3;
            $orderB = isset($typeOrder[$typeB]) ? $typeOrder[$typeB] : 3;

            if ($orderA != $orderB) {
                return $orderA - $orderB;
            }

            // Normalize names by removing trailing dot for comparison
            $nameA = rtrim($a['name'], '.');
            $nameB = rtrim($b['name'], '.');

            if ($nameA != $nameB) {
                // Special handling for '@' to come before subdomains
                if ($nameA === $this->getName()) $nameA = '@'; // Treat apex as '@' for sorting
                if ($nameB === $this->getName()) $nameB = '@';

                if ($nameA === '@' && $nameB !== '@') return -1;
                if ($nameA !== '@' && $nameB === '@') return 1;
                
                // Compare by domain segments, reversed (e.g., www.example.com -> com, example, www)
                $partsA = array_reverse(explode('.', $nameA));
                $partsB = array_reverse(explode('.', $nameB));
                $maxLen = max(count($partsA), count($partsB));
                for ($i = 0; $i < $maxLen; $i++) {
                    $partA = isset($partsA[$i]) ? $partsA[$i] : '';
                    $partB = isset($partsB[$i]) ? $partsB[$i] : '';
                    if ($partA !== $partB) {
                        return strcmp($partA, $partB);
                    }
                }
                // If one is a subdomain of the other, shorter comes first
                if (count($partsA) !== count($partsB)) {
                    return count($partsA) - count($partsB);
                }

            }

            if ($typeA != $typeB) {
                return strcmp($typeA, $typeB);
            }
            
            // For MX, sort by preference
            if ($typeA === 'MX') {
                $prefA = isset($a['preference']) ? (int)$a['preference'] : (isset($a['content']) ? (int)explode(' ', $a['content'])[0] : PHP_INT_MAX);
                $prefB = isset($b['preference']) ? (int)$b['preference'] : (isset($b['content']) ? (int)explode(' ', $b['content'])[0] : PHP_INT_MAX);
                if ($prefA != $prefB) {
                    return $prefA - $prefB;
                }
            }

            // Finally, sort by content if all else is equal
             $contentA = isset($a['content']) ? (is_array($a['content']) ? implode(' ', $a['content']) : $a['content']) : '';
             $contentB = isset($b['content']) ? (is_array($b['content']) ? implode(' ', $b['content']) : $b['content']) : '';
            return strcmp($contentA, $contentB);
        });
    }
}

?>
