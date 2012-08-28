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

if (!(defined("TIME_RANGE_PHP"))) {
	define("TIME_RANGE_PHP", 1);

	$t_tbl=array(
		0  => 0x00000000,
		1  => 0x80000000, 2  => 0xc0000000, 3  => 0xe0000000, 4  => 0xf0000000,
		5  => 0xf8000000, 6  => 0xfc000000, 7  => 0xfe000000, 8  => 0xff000000,
		9  => 0xff800000, 10 => 0xffc00000, 11 => 0xffe00000, 12 => 0xfff00000,
		13 => 0xfff80000, 14 => 0xfffc0000, 15 => 0xfffe0000, 16 => 0xffff0000,
		17 => 0xffff8000, 18 => 0xffffc000, 19 => 0xffffe000, 20 => 0xfffff000,
		21 => 0xfffff800, 22 => 0xfffffc00, 23 => 0xfffffe00, 24 => 0xffffff00,
		25 => 0xffffff80, 26 => 0xffffffc0, 27 => 0xffffffe0, 28 => 0xfffffff0,
		29 => 0xfffffff8, 30 => 0xfffffffc, 31 => 0xfffffffe, 32 => 0xffffffff
	);

	function time_pair($tstr, &$low, &$high) {
		global $t_tbl;
		$tstamp=0;

		$tstamp=strtotime($tstr);

		if (strstr($tstr, "/")) {
			$t_str=reverse_strrchr($tstr, "/");
			$tstamp=strtotime($t_str);
			sscanf(strrchr($tstr, "/"), "/%u", $mask);
		}
		else {
			$tstamp=strtotime($tstr);
			$mask=32;
		}
		if ($mask < 0 || $mask > 32) trigger_error("timemask out of range");

		$low=sprintf("%u", ($tstamp & $t_tbl[$mask]));
		$high=sprintf("%u", ($tstamp | (0xffffffff ^ $t_tbl[$mask])));
	}

	function reverse_strrchr($haystack, $needle) {
		return strrpos($haystack, $needle) ? substr($haystack, 0, strrpos($haystack, $needle)) : false;
	} 
}
?>
