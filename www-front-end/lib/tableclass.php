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

if (!(defined("tableclass_include"))) {
define("tableclass_include", 1);

class tableclass {
	var	$numrows;
	var	$numcols;
	var	$row_arr=array();
	var	$hdr_arr=array();

	var	$table_tag;
	var	$table_closetag;
	var	$trhdr_tag;

	var	$trhdr_closetag;
	var	$tdhdr_tag;
	var	$tdhdr_closetag;

	var	$tr1_tag;
	var	$tr2_tag;
	var	$tr_closetag;

	var	$td_tag;
	var	$td_closetag;

	var	$col_widths;
	var	$show_header;

	function tableclass($iclass = "tblhdr") {
		global $PHPLIB;

		$this->table_tag="<table class='".$iclass."'>";
		$this->table_closetag="</table>";

		$this->trhdr_tag="<tr class='tblhdr'>";
		$this->trhdr_closetag="</tr>";

		$this->tdhdr_tag="<td";
		$this->tdhdr_closetag="</td>";

		$this->tr1_tag="<tr class='tblrow1'>";
		$this->tr2_tag="<tr class='tblrow2'>";

		$this->tr_closetag="</tr>";

		$this->td_tag="<td";
		$this->td_closetag="</td>";

		$this->row_num=0;
		$this->col_widths=-1;
		$this->show_header=0;
	}

	function set_width($width) {
		$this->table_tag="<table class='tableclass' width=\"".$width."\">";
	}

	function add_header() {
		$num=func_num_args();
		$items=func_get_args();

		if ($num < 1) {
			trigger_error("No arguments passed to add_header");
		}

		$this->numcols=$num;

		for ($j=0 ; $j < $num ; $j++) {
			$this->hdr_arr=$items;
		}
		$this->show_header=1;

	}

	function set_cols($num, $widths = -1) {
		$this->numcols=(integer)$num;

		if ($widths != -1) {
			$this->col_widths=$widths;
		}
	}

	function add_row(){
		$num=func_num_args();
		$items=func_get_args();

		if ($num < 1) {
			trigger_error("No arguments passed to add_row");
		}

		if ($this->numcols != $num) {
			trigger_error("Arguments to add_row mismatch cols in header!");
		}

		for ($j=0 ; $j < $num ; $j++) {
			$this->row_arr[$this->row_num]=$items;
		}

		$this->row_num++;
	}

	function get_tdhdr_tag($offset) {
		if ($this->col_widths != -1) {
			return $this->tdhdr_tag . " width=\"".$this->col_widths[$offset]."\">";
		}
		else {
			return $this->tdhdr_tag . ">";
		}
	}

	function get_td_tag($offset) {
		if ($this->col_widths != -1) {
			return $this->td_tag . " width=\"".$this->col_widths[$offset]."\">";
		}
		else {
			return $this->td_tag . ">";
		}
	}

	function sprint_tbl() {
		$trst="";

		$buf=$this->table_tag."\n";

		if ($this->show_header == 1) {
			$buf .= $this->trhdr_tag;

			for ($j=0 ; $j < $this->numcols ; $j++) {
				$buf .= $this->get_tdhdr_tag($j) . $this->hdr_arr[$j] . $this->tdhdr_closetag."\n";
			}

			$buf .= $this->trhdr_closetag."\n";
		}

		for ($j=0 ; $j < $this->row_num ; $j++) {

			if ($j == 0 || ($j % 2) == 0) {
				$trst=$this->tr1_tag;
			}
			else {
				$trst=$this->tr2_tag;
			}

			$buf .= $trst;

			for ($j1=0 ; $j1 < $this->numcols ; $j1++) {
				$buf .= $this->get_td_tag($j1) . $this->row_arr[$j][$j1] . $this->td_closetag."\n";
			}

			$buf .= $this->tr_closetag;
		}

		$buf .= $this->table_closetag."\n";

		return $buf;
	}

	function print_tbl() {
		print $this->sprint_tbl();
	}
} /* class */

}
?>
