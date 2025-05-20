[![ENGINYRING](https://cdn.enginyring.com/img/logo_dark.png)](https://www.enginyring.com)


# NSEdit-WHM: DNS Editor for cPanel WHM

NSEdit-WHM is a web-based DNS editor designed to manage DNS zones through the **cPanel WHM API**. It provides a user-friendly interface for administrators and users (with appropriate permissions) to handle DNS records. This project is a refactored version of the original NSEdit, which was built for the PowerDNS API.

**Author:** ENGINYRING
**Project URL:** [https://github.com/ENGINYRING/nsedit-whm](https://github.com/ENGINYRING/nsedit-whm)

## Features

* **Zone Management:** Add, modify (records), and delete DNS zones.
* **Record Management:** Add, edit, and delete various DNS record types (A, AAAA, CNAME, MX, TXT, SRV, NS, CAA, etc.).
* **Zone Import:** Import BIND-style zone data by pasting raw zone file text during zone creation.
* **Zone Cloning:** Duplicate existing zones to new domain names.
* **Zone Export:** Export zones in BIND-compatible plain text format.
* **DNSSEC Display:** Show DNSSEC key information (DNSKEY and DS records) for zones if configured on the WHM server. (Full DNSSEC management like enabling/disabling or key manipulation is a potential future enhancement).
* **User Management:**
    * Supports multiple users with an internal SQLite database.
    * Admin and regular user roles.
    * Option to link application users to cPanel accounts (`cpanel_username`) for permission delegation.
* **Logging:**
    * Comprehensive logging of user actions within the application (file-based).
    * Optional SQLite database logging with viewing and clearing capabilities for admins.
    * CLI script for rotating database logs.
* **Search Functionality:** Search zones and records within zones.
* **User Interface:** Built with jQuery, jQuery UI, and the jTable plugin for dynamic tables.

## User Support

Multiple users are supported via an internal SQLite database. Users can be designated as administrators or regular users.
Administrators have full access, including user management and site-wide log viewing.
Regular users' ability to add new zones can be configured (`$allowzoneadd` in `config.inc.php`).
Zone access for regular users can be tied to cPanel account ownership by associating an application user with a `cpanel_username`.

## WeFact Login Support (Optional)

NSEdit can optionally authenticate users against the WeFact HostFact API. This allows customers with WeFact accounts to log in to NSEdit using their WeFact credentials. If a user is authenticated via WeFact, their associated cPanel username (if configured correctly in WeFact or mapped) would be used for determining zone permissions. The core DNS operations will still go through the WHM API.

## Requirements

* A web server (e.g., Apache, Nginx) with PHP support (PHP 7.x or higher recommended).
* **PHP Extensions:**
    * `pdo_sqlite` (or `sqlite3` if an older version of `misc.inc.php` is used for DB init - the refactored version uses PDO-style access via SQLite3 class)
    * `curl` (for making API calls)
    * `openssl` (for CSRF token generation and password hashing)
    * `json` (for handling API responses)
* **cPanel & WHM Server:**
    * A functioning cPanel & WHM server.
    * WHM API access enabled.
    * An **API Token** with sufficient permissions (see "Configuring WHM API Access" below).

## Installing NSEdit-WHM

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/ENGINYRING/nsedit-whm.git](https://github.com/ENGINYRING/nsedit-whm.git) /path/to/your/webroot/nsedit-whm
    cd /path/to/your/webroot/nsedit-whm
    ```
    (Or download a release ZIP and extract it).

2.  **Configure:**
    * Copy `includes/config.inc.php-dist` to `includes/config.inc.php`.
    * Edit `includes/config.inc.php` and **carefully fill in all required WHM API settings** and other preferences. See the configuration section below for details.

3.  **Permissions:**
    * Ensure the web server has write permissions to the directory where the SQLite database (`$db_file` defined in `config.inc.php`, e.g., `nsedit-whm/nsedit.db`) will be created/stored.
    * Ensure the web server has write permissions to the log file (`$logfile` in `config.inc.php`) and the log rotation directory (`$logsdirectory` in `config.inc.php`) if database log rotation is used.
    * **Security Note:** It's highly recommended to place the SQLite database and log files *outside* of your web server's public document root if possible, or protect them with appropriate `.htaccess` or server configuration rules if they must reside within it. The default paths in the refactored `config.inc.php` place them one level above the `includes` directory (e.g., in the project root).

4.  **Access:**
    * Navigate to the URL where you installed NSEdit-WHM (e.g., `http://yourserver.com/nsedit-whm/`).
    * The default login credentials (if no database exists and it's created on first run) are typically `admin` / `password` (as defined by `$default_user` and `$default_pass` in `config.inc.php`).
    * **Change the default admin password immediately after your first login!**

## Configuration (`includes/config.inc.php`)

The following are crucial settings for WHM integration:

* `$whm_host`: Your WHM server's hostname or IP address (e.g., `whm.yourserver.com`).
* `$whm_port`: The WHM API port (usually `2087` for SSL, `2086` for non-SSL).
* `$whm_user`: The WHM username that will be used for API calls (e.g., `root` or a reseller with appropriate permissions).
* `$whm_api_token`: The API Token generated for the `$whm_user`. **Keep this token secure.**
* `$whm_proto`: `https` (recommended) or `http`.
* `$whm_sslverify`: `true` or `false`. Set to `true` in production if WHM has a valid SSL certificate.

Other important settings include database path (`$db_file`), logging options (`$loglevel`, `$logfile`), and authentication type (`$auth_type`).

## Configuring WHM API Access

NSEdit-WHM requires a WHM API Token to interact with your server.

1.  **Log in to WHM** as `root` or a reseller account that has the necessary privileges.
2.  Navigate to **Development -> Manage API Tokens**.
3.  Click **"Generate Token"**.
4.  Give the token a name (e.g., `nsedit_api_token`).
5.  **Permissions (ACLs):** Crucially, you must grant this token the necessary permissions. For full DNS management, you will likely need to grant permissions related to:
    * `list-accts` (to list domains/accounts)
    * `adddns` (to add new zones)
    * `dumpzone` (to read zone records)
    * `editzonerecord` (to modify existing records)
    * `addzonerecord` (to add new records to an existing zone)
    * `removezonerecord` (to delete individual records)
    * `killdns` (to delete entire zones)
    * DNSSEC related permissions if you intend to manage/view DNSSEC keys (e.g., `export_zone_dnskey`, `fetch_ds_records_for_domains`, and potentially others like `enable_dnssec_for_domains`).
    * It's often easier to grant a broad set of DNS-related permissions or even "All" if this token is used exclusively for NSEdit on a trusted server. However, for better security, grant only the minimum required privileges.
6.  Save the token. **Copy the generated API token immediately and securely.** You will not be able to see it again.
7.  Enter this token into the `$whm_api_token` variable in your `includes/config.inc.php` file.

## CLI Scripts

* `rotate-logs.php`: This script can be run via cron to archive database logs to files and clear the database log table. Ensure `$allowrotatelogs` and `$logsdirectory` are set in `config.inc.php`.

## Screenshots

*(This section should be updated with new screenshots reflecting the WHM version of NSEdit.)*

## Troubleshooting

* **"Authentication failed" / "API Error"**:
    * Double-check your WHM API settings in `config.inc.php` (`$whm_host`, `$whm_port`, `$whm_user`, `$whm_api_token`).
    * Ensure the API token has the correct permissions in WHM.
    * Verify network connectivity from your web server to the WHM API port.
    * Check `$whm_sslverify` if using HTTPS; set to `false` temporarily for self-signed certs (not recommended for production).
* **"CSRF token validation failed"**: Try clearing your browser cache/cookies for the site or refreshing the page.
* **Zone/Record operations not working**: Check the NSEdit application log (`$logfile`) and the WHM API log (`/usr/local/cpanel/logs/api_log`) for more detailed error messages.
* **Database errors**: Ensure the path to `$db_file` is correct and the web server has write permissions to the file and its directory.

## Contributing

Contributions are welcome! Please feel free to fork the repository, make your changes, and submit a pull request.

## License

This project is typically licensed under a common open-source license (e.g., MIT, GPL). Please refer to the `LICENSE` file in the repository (if one exists) or contact the author for specific licensing information. (Assuming a standard open-source license based on original project nature).

This updated README.md provides a comprehensive overview of NSEdit-WHM, its features, installation, and configuration specific to the cPanel WHM API backend. I've noted where screenshots should be updated and made the author and project URL prominent.

The next logical steps for you would be:

    Thorough Testing: As emphasized before, test all functionalities.

    Implement UI-Triggered Log Rotation: If desired, add the rotate action to logs.php.

    Full DNSSEC Management: If you need more than just displaying DNSSEC keys (e.g., enabling DNSSEC, adding/removing keys via the UI), those WhmApi.php methods and corresponding zones.php actions would need to be built out.

    Review minor files like session.inc.php, wefactauth.inc.php (if used), and scheme.sql for any final adjustments.

    Update screenshots in the README.
