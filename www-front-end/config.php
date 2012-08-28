<?php

if (!(defined("config_master_include"))) {
	define("config_master_include", 1);

	// Web Server location stuff
	$PHPLIB["uri_base"]="http://localhost/unicornscan/";		// http://vhost.domain.tld/something/

	$PHPLIB["filesystem_base"]="/var/www/htdocs/unicornscan/";		// Base directory content is in
	$PHPLIB["filesystem_phplib"]="/var/www/htdocs/unicornscan/lib/";	// Where phplib is
	$PHPLIB["filesystem_temporary"]="/tmp/";			// Where can i write files to?

	// DataBase Variables
	$PHPLIB["database_name"]="scan"; 		// change this for sure , its the database name
	$PHPLIB["database_type"]="pgsql";		// pgsql, mysql, youll need the right class though
	$PHPLIB["database_username"]="scan";
	$PHPLIB["database_password"]="scanit!";
	$PHPLIB["database_host"]="127.0.0.1";
	$PHPLIB["database_db"]["default"]="";

	// Time
	$PHPLIB["time_format"]="%D %I:%M:%S %p";			// strftime format string

	// formclass2.php stuff
	$PHPLIB["formclass_warnimage"]="exl.gif";			// warning image for invalid forms

} // Double Inclusion detection

require("./lib/connect_todb.php");
require("./lib/session_handler.php");

?>
