<?php
/**********************************************************************
 * Copyright (C) (2005) (Jack Louis) <jack@rapturesecurity.org>       *
 *                                                                    *
 * This program is free software; you can redistribute it and/or      *
 * modify it under the terms of the GNU General Public License        *
 * as published by the Free Software Foundation; either               *
 * version 2 of the License, or (at your option) any later            *
 * version.                                                           *
 *                                                                    *
 * This program is distributed in the hope that it will be useful,    *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
 * GNU General Public License for more details.                       *
 *                                                                    *
 * You should have received a copy of the GNU General Public License  *
 * along with this program; if not, write to the Free Software        *
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.          *
 **********************************************************************/

if ((!(defined("oopdbclass_include")))||oopdbclass_include != 1) {
	define("oopdbclass_include", 1);

	global $PHPLIB;

	class oop_db {
		var $username;
		var $password;
		var $server;
		var $port;
		var $db;
		var $conn_str;
		var $persistant;

		var $query;

		var $ass_flg; /* indexed or associative array? 1=associative */
		var $resultarr;
		var $row_num;
		var $numrows;
		var $link;
		var $resultptr;

		/* Constructor function..... */
		function oop_db($debug = 0) {
			global $PHPLIB;

			$this->ass_flg=0;
			$this->resultarr=array();
			$this->row_num=0;
			$this->numrows=0;
			$this->link="";
			$this->resultptr="";

			$this->query="";

			$this->username="postgres";
			$this->password="";
			$this->server="127.0.0.1";
			$this->port=5432;
			$this->db="template1";
			$this->conn_str="";
			$this->persistant=0;
		}

		/* Code to create a connection to a PostGreSQL server */
		function dbconnect() {
			/* Kludge, dont connect here, connect in select_db() */
		}

		function select_db($db = "") {
			if (strlen($db)) {
				$this->db=$db;
			}
			$this->conn_str="user=".$this->username." password=".$this->password." dbname=".$this->db." host=".$this->server;
			if ($this->persistant) {
				$function="pg_pconnect";
			}
			else {
				$function="pg_connect";
			}
			if (!($this->link=$function($this->conn_str))) {
				trigger_error("cant connect to database, PostGreSQL error: '".pg_errormessage()."'", E_USER_ERROR);
			}
		}

		function aquerydb($query) {
			/* Checks for a zero length query, queries and does error reporting */
			if (!(strlen($query))) {
				trigger_error("empty query passed to aquerydb", E_USER_ERROR);
				return -1;
			}
			$this->query=$query;

			$this->row_num=0;
			if (!(@$this->resultptr=pg_exec($this->link, $this->query))) {
				trigger_error("pgsql_query() in oop_db (pgsql): '".pg_errormessage()."'", E_USER_ERROR);
			}
			@$this->numrows=pg_numrows($this->resultptr);
		}

		function agetassarr($query) {
			/* Checks for a zero length query, queries and does error reporting */
			if (!(strlen($query))) {
				trigger_error("empty query passed to agetassarr", E_USER_ERROR);
				return -1;
			}

			$this->query=$query;

			$this->row_num=0;
			$this->ass_flg=1;
			if (!($this->resultptr=pg_exec($this->link, $this->query))) {
				trigger_error("pgsql_query() in oop_db (pgsql): '".pg_errormessage()."'", E_USER_ERROR);
			}
			@$this->numrows=pg_numrows($this->resultptr);
		}

		function data_step() {
			@$this->resultarr=pg_fetch_array($this->resultptr, $this->row_num++);
		}

		function _escape_string($in) {
			return pg_escape_string($in);
		}

		function destructor() {
			if ($this->link) {
				pg_close($this->link);
			}
		}
	}

}
?>
