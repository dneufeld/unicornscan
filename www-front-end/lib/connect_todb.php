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

if (!(defined("connect_todb_include"))) {
	define("connect_todb_include",1);

	global $PHPLIB;

        require($PHPLIB["filesystem_mylib"].$PHPLIB["database_type"]."dbclass.php");

        if ((!(isset($db)))||(!(is_object($db)))) {
                $db=new oop_db(0);
        }

        $db->username=$PHPLIB["database_username"];
        $db->password=$PHPLIB["database_password"];
        $db->server=$PHPLIB["database_host"];
        $db->dbconnect();

        $db->select_db($PHPLIB["database_name"]);
	if (isset($PHPLIB["database_db"])) {
		$PHPLIB["database_db"]=$db;
	}
}
?>
