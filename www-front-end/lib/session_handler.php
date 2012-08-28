<?php
/******************************************************************************
 *    Copyright (C) 2002,2006 Jack Louis                                      *
 *                                                                            *
 *    This program is free software; you can redistribute it and/or modify    *
 *    it under the terms of the GNU General Public License as published by    *
 *    the Free Software Foundation; either version 2 of the License, or       *
 *    (at your option) any later version.                                     *
 *                                                                            *
 *    This program is distributed in the hope that it will be useful,         *
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 *    GNU General Public License for more details.                            *
 *                                                                            *
 *    You should have received a copy of the GNU General Public License       *
 *   along with this program; if not, write to the Free Software              *
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA*
 ******************************************************************************/

if (!(defined("session_handler_include"))) {
	define("session_handler_include", 1);

	if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") {
		$proto="https://";
	}
	else {
		$proto="http://";
	}

	require($PHPLIB["filesystem_phplib"]."connect_todb.php");

	function get_sessid() {
		$session_id="";

		$fp=fopen("/dev/urandom", "r");
		if (!($fp)) {
			exit;
		}

		$rndbytes=fread($fp, 32);
		fclose($fp);

		if ($rndbytes == FALSE) {
			exit;
		}
		$session_id=base64_encode(pack("N", time()))."!";
		$session_id .= base64_encode($rndbytes);

		return $session_id;
	}

	function session_open($save_path, $sess_name) {
		return true;
	}

	function session_close() {
		return true;
	}

	function session_kill($sess_id) {
		global $PHPLIB;

		$db=$PHPLIB["database_db"];

		$query="delete from uni_session where sessid='".$db->_escape_string($sess_id)."'";

		$db->aquerydb($query);

		return true;
	}

	function session_read($sess_id) {
		global $PHPLIB;

		$db=$PHPLIB["database_db"];

		$curtime=time();
		$dsessid=$db->_escape_string($sess_id);

		$query="select data from uni_session where sessid='".$dsessid."'";
		$db->aquerydb($query);

		if ($db->numrows == 0) {
			$ua=$db->_escape_string($_SERVER["HTTP_USER_AGENT"]);
			$ra=$db->_escape_string($_SERVER["REMOTE_ADDR"]);
			@$rh=$db->_escape_string(gethostbyaddr($ra));
			$mtime=$curtime;
			$atime=$curtime;
			$ctime=$curtime;

			$query=<<<EOF
insert into
	uni_session (sessid, remote_addr, remote_host, user_agent, c_time, m_time, a_time, uid, gid)
values
	('$dsessid', '$ra', '$rh', '$ua', $ctime, $mtime, $atime, -1, -1);
EOF;

			$db->aquerydb($query);
			return "";
		}

		$db->data_step();
		$sessdata=$db->resultarr[0];

		$query=<<<EOF
update
	uni_session
set
	m_time=$curtime, a_time=$curtime
where
	sessid='$dsessid'
EOF;
		$db->aquerydb($query);

		if (strlen($sessdata) > 0) {
			return $sessdata;
		}
		else {
			return "";
		}
	}

	function session_write($sess_id, $val) {
		global $PHPLIB;

		$db=$PHPLIB["database_db"];

		if (strlen($val) < 1) {
			return true;
		}

		$sessdata=$db->_escape_string($val);
		$dsessid=$db->_escape_string($sess_id);
		$curtime=time();


		$query=<<<EOF
update
	uni_session
set
	data='$sessdata', m_time=$curtime
where
	sessid='$dsessid'
EOF;


		$db->aquerydb($query);

		return true;
	}

	function session_gc() {

		/* we dont do this */
		return true;
	}

	/*
	 * now we make the session active
	 */

	session_set_save_handler(
		"session_open",
		"session_close",
		"session_read",
		"session_write",
		"session_kill",
		"session_gc"
	);

	if (isset($_SESSION["sessid"])) {
		$sessid=$_SESSION["sessid"];
	}
	else if (isset($_COOKIE["sessid"])) {
		$sessid=$_COOKIE["sessid"];
	}
	else if (isset($_POST["sessid"])) {
		$sessid=$_POST["sessid"];
	}
	else if (isset($_GET["sessid"])) {
		$sessid=$_GET["sessid"];
	}
	else {

		session_name("sessid");

		$sessid=get_sessid();
		session_id($sessid);
		session_start();

		$uri=$proto.$_SERVER["HTTP_HOST"].$_SERVER["PHP_SELF"]."?sessid=".$sessid;

		if (!(headers_sent())) {
			header("P3P: CP='CAO DSP OUR'");
			header("Location: ".$uri);

			print "you dont have a session, come again\n";
			exit;
		}
		exit;
	}

	/* now validate the session id */

	$query="select c_time from uni_session where sessid='".$db->_escape_string($sessid)."'";
	$db->aquerydb($query);

	if ($db->numrows != 1) {
		/* Now delete the cookie so to avoid loops ;) */
		session_name("sessid");
		$cookie=session_get_cookie_params();

		setcookie(session_name(), "", 0, $cookie["path"], $cookie["domain"]);
		$uri=$proto.$_SERVER["HTTP_HOST"].$_SERVER["PHP_SELF"];

		/*
		 * just in case the browser sucks, we dont
		 * want it looping and bogging the server
		 */
		usleep(2000);

		header("P3P: CP='CAO DSP OUR'");
		header("Location: ".$uri);

		print "Your session is dumb, come again\n";
		exit;
	}
	else {
		header("P3P: CP='CAO DSP OUR'");
		session_name("sessid");
		session_id($sessid);
		@session_start();
	}

} /* include protect */
?>
