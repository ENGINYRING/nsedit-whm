<?php

// Ensure config is loaded. It's good practice to include it where needed,
// or ensure it's loaded by a bootstrap/front-controller.
// For this class, it's assumed that global WHM config variables are available.
// If not, they should be passed into the constructor.
if (file_exists(__DIR__ . '/../config.inc.php')) {
    include_once(__DIR__ . '/../config.inc.php');
} elseif (file_exists(__DIR__ . '/../../includes/config.inc.php')) { // If ApiHandler is in a sub-sub-directory
    include_once(__DIR__ . '/../../includes/config.inc.php');
}


class ApiHandler {
    public $headers;
    public $hostname;
    public $port;
    // public $auth; // Replaced by whm_user and whm_api_token
    public $whm_user;
    public $whm_api_token;
    public $proto;
    public $sslverify;
    public $curlh;
    public $method;
    public $content; // Can be a query string for POST or JSON string
    // public $apiurl; // Removed - PowerDNS specific
    public $url; // This will now hold the WHM function and its query string, e.g., "listaccts?api.version=1"
    public $json; // Stores the decoded JSON response
    public $last_error; // Store last cURL or API error
    public $last_http_code; // Store last HTTP code

    public function __construct() {
        // Access global WHM configuration variables
        // These should be defined in config.inc.php
        global $whm_host, $whm_port, $whm_user, $whm_api_token, $whm_proto, $whm_sslverify;

        $this->headers = array();
        $this->hostname = $whm_host;
        $this->port = $whm_port;
        $this->whm_user = $whm_user;
        $this->whm_api_token = $whm_api_token;
        $this->proto = $whm_proto;
        $this->sslverify = (bool)$whm_sslverify; // Ensure boolean
        $this->curlh = curl_init();
        $this->method = 'GET'; // Default method
        $this->content = null;
        $this->url = '';
        $this->json = null;
        $this->last_error = null;
        $this->last_http_code = null;

        if (empty($this->hostname) || empty($this->whm_user) || empty($this->whm_api_token)) {
            throw new Exception("WHM API connection details (host, user, token) are not configured.");
        }
    }

    public function addheader($field, $content) {
        $this->headers[$field] = $content;
    }

    private function authheaders() {
        // Set WHM Authorization header
        $this->addheader('Authorization', 'whm ' . $this->whm_user . ':' . $this->whm_api_token);
    }

    private function curlopts() {
        $this->headers = array(); // Reset headers for each call before setting auth
        $this->authheaders(); // Set WHM specific auth headers
        $this->addheader('Accept', 'application/json'); // WHM API returns JSON

        if (defined('CURL_RESET')) { // curl_reset was added in PHP 5.5
            curl_reset($this->curlh);
        } else {
            // For older PHP, re-initialize and close to simulate reset
            if (is_resource($this->curlh)) {
                curl_close($this->curlh);
            }
            $this->curlh = curl_init();
        }
        
        curl_setopt($this->curlh, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($this->curlh, CURLOPT_TIMEOUT, 60); // Set a reasonable timeout
        curl_setopt($this->curlh, CURLOPT_CONNECTTIMEOUT, 30); // Connection timeout

        if (strcasecmp($this->proto, 'https') == 0) {
            curl_setopt($this->curlh, CURLOPT_SSL_VERIFYPEER, $this->sslverify);
            curl_setopt($this->curlh, CURLOPT_SSL_VERIFYHOST, $this->sslverify ? 2 : 0);
        }

        $setheaders = array();
        foreach ($this->headers as $k => $v) {
            array_push($setheaders, $k . ": " . $v);
        }
        curl_setopt($this->curlh, CURLOPT_HTTPHEADER, $setheaders);
    }

    private function baseurl() {
        $ip = $this->hostname;
        // Check if hostname is an IPv6 address
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip = '[' . $ip . ']'; // cURL requires brackets for IPv6 numeric addresses
        }
        return $this->proto . '://' . $ip . ':' . $this->port;
    }

    private function go() {
        $this->curlopts(); // Set cURL options including headers

        $full_url = $this->baseurl() . '/json-api/' . $this->url;

        // For POST requests, set content type if JSON content is provided
        if ($this->method === 'POST' && !is_null($this->content)) {
            // WHM API 1 often uses x-www-form-urlencoded for POST, even if it looks like GET params
            // If $this->content is an array, build a query string. If it's a JSON string, set appropriate header.
            if (is_array($this->content)) {
                 // This was for JSON content type, WHM API 1 usually uses query string for POST too
                // $this->addheader('Content-Type', 'application/json');
                // curl_setopt($this->curlh, CURLOPT_POSTFIELDS, json_encode($this->content));
                // For WHM API 1, POST data is often like GET parameters (application/x-www-form-urlencoded)
                // The $this->url should already contain these for POST if they are not in a request body.
                // If $this->content is used for POST body, ensure it's a query string.
                // For simplicity, we assume if $this->content is set for POST, it's a query string.
                 curl_setopt($this->curlh, CURLOPT_POSTFIELDS, http_build_query($this->content));

            } elseif (is_string($this->content)) {
                // If it's a pre-formatted query string or JSON string
                // If JSON, ensure Content-Type was set appropriately before calling go()
                // For now, assume it's a query string if string.
                curl_setopt($this->curlh, CURLOPT_POSTFIELDS, $this->content);
            }
        }


        switch (strtoupper($this->method)) {
            case 'POST':
                curl_setopt($this->curlh, CURLOPT_POST, 1);
                // CURLOPT_POSTFIELDS is set above if $this->content is present
                break;
            case 'GET':
                curl_setopt($this->curlh, CURLOPT_HTTPGET, 1); // More explicit than CURLOPT_POST = 0
                break;
            case 'DELETE':
            case 'PATCH':
            case 'PUT':
                curl_setopt($this->curlh, CURLOPT_CUSTOMREQUEST, strtoupper($this->method));
                if (!is_null($this->content)) {
                     if (is_array($this->content)) {
                        curl_setopt($this->curlh, CURLOPT_POSTFIELDS, http_build_query($this->content));
                    } elseif (is_string($this->content)) {
                        curl_setopt($this->curlh, CURLOPT_POSTFIELDS, $this->content);
                    }
                }
                break;
            default:
                // Assume GET if not specified or unknown
                curl_setopt($this->curlh, CURLOPT_HTTPGET, 1);
                break;
        }

        curl_setopt($this->curlh, CURLOPT_URL, $full_url);

        $return_content = curl_exec($this->curlh);
        $this->last_http_code = curl_getinfo($this->curlh, CURLINFO_HTTP_CODE);
        $curl_errno = curl_errno($this->curlh);
        $curl_error = curl_error($this->curlh);

        if ($curl_errno) {
            $this->last_error = "cURL Error ($curl_errno): " . $curl_error . " when trying to access " . $full_url;
            throw new Exception($this->last_error);
        }

        $this->json = json_decode($return_content, true);

        // Check for WHM API specific errors (typically in 'metadata')
        if (isset($this->json['metadata']['result']) && $this->json['metadata']['result'] == 0) {
            $error_message = isset($this->json['metadata']['reason']) ? $this->json['metadata']['reason'] : 'Unknown WHM API error.';
            if (isset($this->json['errors']) && is_array($this->json['errors']) && !empty($this->json['errors'][0])) {
                 $error_message .= " Details: " . $this->json['errors'][0];
            }
            $this->last_error = "WHM API Error (HTTP {$this->last_http_code}): " . $error_message;
            throw new Exception($this->last_error);
        }
        // Check for general HTTP errors not caught by WHM's metadata.result
        elseif ($this->last_http_code < 200 || $this->last_http_code >= 300) {
            $this->last_error = "HTTP Error {$this->last_http_code} for " . $full_url . ". Response: " . substr($return_content, 0, 500);
            if ($this->last_http_code == 401) {
                 $this->last_error = "Authentication failed (HTTP 401). Check WHM user and API token permissions for: " . $this->url;
            }
            throw new Exception($this->last_error);
        }
        
        // Check if JSON decoding failed for a successful HTTP code
        if ($this->json === null && json_last_error() !== JSON_ERROR_NONE && !empty(trim($return_content))) {
            $this->last_error = "Failed to decode JSON response (HTTP {$this->last_http_code}). Response: " . substr($return_content, 0, 500);
            throw new Exception($this->last_error);
        }
    }

    /**
     * Makes the API call.
     * The $this->url property should be set to the WHM function name and its query string
     * (e.g., "listaccts?api.version=1&search=example.com&searchtype=domain").
     * The $this->method should be set (e.g., 'GET', 'POST').
     * For POST requests that use a request body, $this->content should be set.
     */
    public function call() {
        // $this->url is now expected to be the function and its parameters like "listzones?api.version=1"
        // The "/json-api/" prefix and base server URL are handled in go() and baseurl().
        if (empty($this->url)) {
            throw new Exception("API URL (function name and parameters) not set.");
        }
        $this->go();
    }

    public function __destruct() {
        if (is_resource($this->curlh)) {
            curl_close($this->curlh);
        }
    }
}

?>
