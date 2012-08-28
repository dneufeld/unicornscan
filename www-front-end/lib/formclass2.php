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

if (!(defined("formclass2_include"))) {
	define("formclass2_include",1);

	global $PHPLIB;

class formclass {
	var $action;
	var $method;
	var $enctype;
	var $proto;

	var $NORESET;
	var $max_cols;

	var $inputs;
	var $row_cnt;
	var $col_cnt;
	var $row_tmpnum;

	var $prepend_done;
	var $prepend;
	var $prerow_cnt;
	var $precol_cnt;
	var $prerow_tmpnum;

	var $hidden;

	var $outbuf;

	var $row_class_toggle;

	var $form_extra;
	var $table_extra;
	var $defaults;

	var $default_method;

	var $warnimage;

	var $validate_errors;
	var $invalid_arr;
	var $error_str1;
	var $error_str2;
	var $reconstructed_vars;

	var $form_align;

	var $shutdown_code;

	var $tmpfile_init;
	var $tmpdir;
	var $tmpfile;

	function formclass($pDEBUG=0) {
		global $PHPLIB, $NORESET;
		if ($NORESET == 1) {
			$this->NORESET=1;
		}

		$this->inputs[0][0]="";
		$this->row_cnt=0;
		$this->col_cnt[0]=0;
		$this->row_tmpnum=0;

		$this->prepend_done=0;
		$this->prepend=array();
		$this->prerow_cnt=0;
		$this->precol_cnt[0]=0;
		$this->prerow_tmpnum=0;

		$this->max_cols=0;

		$this->enctype="application/x-www-form-urlencoded";
		$this->method="post";
		$this->action=$_SERVER["PHP_SELF"];
		$this->row_class_toggle=0;
		$this->table_extra="";
		$this->table_css_class="table";
		$this->form_css_class="form";
		$this->form_align="center";
		$this->form_extra="";
		$this->defaults["formclass_version"]="2.0";

		if (isset($PHPLIB["formclass_warnimage"])) {
			$this->warnimage=$PHPLIB["formclass_warnimage"];
		}
		else {
			$this->warnimage="exl.gif";
		}
		
		$this->validate_errors=array();
		$this->invalid_arr=array();
		$this->reconstructed_vars=array();
		$this->error_str2="Please correct the following fields in highlighted below";
	}

	function reset() {
		/* this is somewhat stupid but sometimes useful */
		$this->formclass();
	}

	/* XXX FIXME this function could be a security hole */
	function reconstruct_post_vars() {
		if ($_SERVER["REQUEST_METHOD"] != "POST") {
			return;
		}

		for ($j=0 ; $j < count ($this->inputs) ; $j++) {
			for ($j1=0 ; $j1 < count($this->inputs[$j]) ; $j1++) {
				$input_name=$this->inputs[$j][$j1]["name"];
				if (!(strlen($input_name))) continue;
				// XXX Alright here is how this will work
				// if there is a POST var with the same name
				// as an input but it has a _a appended then loop
				// and cat data from a-z till the _? is unset
				if (!(isset($_POST[$input_name."_a"]))) continue;
				// if we passed that "check" then its time to
				// reconstruct the input value from the _a-z vars
				$reconstructed="";
				switch ($this->inputs[$j][$j1]["type"]) {
					case 'datetime':
						$reconstructed=$_POST[$input_name."_a"].
						"/".$_POST[$input_name."_b"].
						"/".$_POST[$input_name."_c"].
						" ".$_POST[$input_name."_d"].
						":".$_POST[$input_name."_e"].
						" ".$_POST[$input_name."_f"];
						break;
					case 'date':
						$reconstructed=$_POST[$input_name."_a"].
						"/".$_POST[$input_name."_b"].
						"/".$_POST[$input_name."_c"];
						break;
					case 'time':
						$reconstructed=$_POST[$input_name."_a"].
						":".$_POST[$input_name."_b"].
						" ".$_POST[$input_name."_c"];
						break;
					case 'percent':
						$reconstructed=$_POST[$input_name."_a"].
						".".$_POST[$input_name."_b"];
						break;
					case 'ipaddress':
						$reconstructed=$_POST[$input_name."_a"].
						".".$_POST[$input_name."_b"].
						".".$_POST[$input_name."_c"].
						".".$_POST[$input_name."_d"];
						break;
					case 'money':
						$reconstructed="$".
						$_POST[$input_name."_a"].
						".".$_POST[$input_name."_b"];
						break;
					default:
						trigger_error("Unknown reconstruction type ".$this->inputs[$j][$j1]["type"],E_USER_WARNING);
				}
				if (strlen($reconstructed)) {
					$this->reconstructed_vars[$input_name]=$reconstructed;
				}
			}
		}
	}

	function get_data() {
		$this->reconstruct_post_vars();
		$arr=$_REQUEST;
		@reset($this->reconstructed_vars);
		while (list($key,$value)=each($this->reconstructed_vars)) {
			$arr[$key]=$value;
		}
		return $arr;
	}

	function new_desc($desc,$extra="",$visu="") {
		$rows=$this->row_cnt;
		$cols=$this->col_cnt[$this->row_cnt];

		$this->inputs[$rows][$cols]["type"]="desc";
		$this->inputs[$rows][$cols]["name"]="";
		$this->inputs[$rows][$cols]["desc"]=$desc;
		$this->inputs[$rows][$cols]["extra"]=$extra;
		$this->inputs[$rows][$cols]["visu"]=$visu;
		++$this->col_cnt[$this->row_cnt];
	}

	function prepend_desc($desc, $extra="", $visu="") {
		$rows=$this->prerow_cnt;
		$cols=$this->precol_cnt[$this->prerow_cnt];

		$this->prepend[$rows][$cols]["type"]="desc";
		$this->prepend[$rows][$cols]["name"]="";
		$this->prepend[$rows][$cols]["desc"]=$desc;
		$this->prepend[$rows][$cols]["extra"]=$extra;
		$this->prepend[$rows][$cols]["visu"]=$visu;
		++$this->precol_cnt[$this->prerow_cnt];
	}
		

	function new_title($desc,$extra="",$visu="") {
		$rows=$this->row_cnt;
		$cols=$this->col_cnt[$this->row_cnt];

		$this->inputs[$rows][$cols]["type"]="title";
		$this->inputs[$rows][$cols]["name"]="";
		$this->inputs[$rows][$cols]["desc"]=$desc;
		$this->inputs[$rows][$cols]["extra"]=$extra;
		$this->inputs[$rows][$cols]["visu"]=$visu;
		++$this->col_cnt[$this->row_cnt];
	}

	function prepend_title($desc,$extra="",$visu="") {
		$rows=$this->prerow_cnt;
		$cols=$this->precol_cnt[$this->prerow_cnt];

		$this->prepend[$rows][$cols]["type"]="title";
		$this->prepend[$rows][$cols]["name"]="";
		$this->prepend[$rows][$cols]["desc"]=$desc;
		$this->prepend[$rows][$cols]["extra"]=$extra;
		$this->prepend[$rows][$cols]["visu"]=$visu;
		++$this->precol_cnt[$this->prerow_cnt];
	}

	function new_input($type,$name,$extra,$visu="") {
		if (!(strlen(trim($type)))) return -1;
		$rows=$this->row_cnt;
		$cols=$this->col_cnt[$this->row_cnt];

		if ($type == "file") {
			$this->enctype="multipart/form-data";
		}

		$this->inputs[$rows][$cols]["type"]=$type;
		$this->inputs[$rows][$cols]["name"]=$name;
		$this->inputs[$rows][$cols]["desc"]="";
		$this->inputs[$rows][$cols]["extra"]=$extra;
		$this->inputs[$rows][$cols]["visu"]=$visu;
		++$this->col_cnt[$this->row_cnt];
	}

	function prepend_input($type,$name,$extra,$visu="") {
		if (!(strlen(trim($type)))) return -1;
		$rows=$this->prerow_cnt;
		$cols=$this->precol_cnt[$this->prerow_cnt];

		if ($type == "file") {
			$this->enctype="multipart/form-data";
		}

		$this->prepend[$rows][$cols]["type"]=$type;
		$this->prepend[$rows][$cols]["name"]=$name;
		$this->prepend[$rows][$cols]["desc"]="";
		$this->prepend[$rows][$cols]["extra"]=$extra;
		$this->prepend[$rows][$cols]["visu"]=$visu;
		++$this->precol_cnt[$this->prerow_cnt];
	}

	function new_textarea($type,$name,$extra,$visu) {
		if (!(strlen(trim($type)))) return -1;
		$rows=$this->row_cnt;
		$cols=$this->col_cnt[$this->row_cnt];

		$this->inputs[$rows][$cols]["type"]=$type;
		$this->inputs[$rows][$cols]["name"]=$name;
		$this->inputs[$rows][$cols]["desc"]="";
		$this->inputs[$rows][$cols]["extra"]=$extra;
		$this->inputs[$rows][$cols]["visu"]=$visu;
		++$this->col_cnt[$this->row_cnt];
	}

	function add_hidden($name,$value) {
		$this->hidden[urlencode($name)]=urlencode($value);
	}

	function new_row() {
		$this->row_cnt++;
		$this->col_cnt[$this->row_cnt]=0;
		$this->row_tmpnum=0;
	}

	function prepend_row() {
		$this->prerow_cnt++;
		$this->precol_cnt[$this->prerow_cnt]=0;
		$this->prerow_tmpnum=0;
	}

	function get_inputs() {
		return $this->inputs;
	}

	function set_inputs($array) {
		$this->inputs=$array;
	}

	function set_invalid($input_name) {
		$this->invalid_arr[$input_name]=1;
	}

	function get_input_html($input_arr,$cols,$max_cols) {

		$visu="";
		if (!(is_array($input_arr))) return -1;
		$type=$input_arr["type"];
		$name=$input_arr["name"];
		$desc=$input_arr["desc"];
		$extra=$input_arr["extra"];
		$visu=$input_arr["visu"];

		$input_str="";
		$td_str="";

		if (is_string($extra) && $extra[0] == "\$") {
			$tmp=str_replace("\$","",$extra); $extra=$tmp;
			global $$extra;
			$tmp=$$extra;
			$extra=$tmp;
		}

		if (is_array($visu)) {
			@reset($visu);
			while (list($key,$value)=each($visu)) {
				if (stristr($key,"input_")) {
					$attr=str_replace("input_","",$key);
					$input_str .= " ".$attr."=\"".$value."\"";
				}
				if (stristr($key,"td_")) {
					if ($this->invalid_arr[$name] != 1) {
						$attr=str_replace("td_","",$key);
						$td_str .= " ".$attr."=\"".$value."\"";
					}
				}
			}
		}
		if (isset($this->invalid_arr[$name]) && $this->invalid_arr[$name] == 1) {
			$td_str .= " class='formerror'";
		}
		$colspan=(int)($max_cols / $cols);

		if ($this->row_tmpnum == 0) {
			if ($type != "title") {
				$style=$this->get_tr_class();
			}
			else {
				$style='formtitle';
			}
			$buf="   <tr class='".$style."'>\n".
			"    <td colspan=\"$colspan\"".$td_str.">\n";
		}
		else {
			$buf="    <td colspan=\"$colspan\"".$td_str.">\n";
		}
		$this->row_tmpnum += (int)($max_cols / $cols);

		switch ($type) {
			case 'text':
				$value=$this->get_var($name);
				$buf .= <<<EOF
     <input type="text" name="$name" class='forminput' value="$value"$input_str/>
EOF;
				break;
			case 'textarea':
				$value=$this->get_var($name);
				$buf .= <<<EOF

    <textarea class='formtextarea' name="$name"$input_str>$value</textarea>
EOF;
				break;
			case 'button':
				$value=$this->get_var($name);
				$buf .= <<<EOF
    <input type="$name" class='formbutton' name="$name" value="$value"$input_str>
EOF;
				break;

			case 'password':
				$value=$this->get_var($name);
				$buf .= <<<EOF
     <input type="password" class='formpassword' name="$name" value="$value"$input_str/>
EOF;
				break;
			case 'title':
				$buf .= "  ".$desc;
				break;

			case 'desc':
				$buf .= "     ".$desc;
				break;

			case 'file':
				$buf .= <<<EOF
<input type="file" class='formfile' name="$name"$input_str/>

EOF;
				break;

			case 'select':
				$buf .= <<<EOF
     <select class='formselect' name="$name"$input_str>

EOF;
				$ar=explode(",", $extra);
				for ($j=0; $j < count($ar) ; $j++) {
					if (strstr($ar[$j], ":")) {
						$a2=explode(":",$ar[$j]);
						$value=urlencode($a2[0]);
						$desc=htmlspecialchars($a2[1]);
						unset($a2);
					}
					else {
						$value=urlencode($ar[$j]);
						$desc=htmlspecialchars($ar[$j]);
					}

					if ($this->get_var($name) == $value) {
						$selected=" selected";
					}
					else {
						$selected="";
					}

					$buf .= "      <option value=\"".
					$value."\"".$selected.">".$desc.
					"</option>\n";
				}
				unset($ar);
				$buf .= <<<EOF
     </select>
EOF;

				break;

			case 'checkbox':
				$cur_val=$this->get_var($name);
				if ($cur_val == "on"||$cur_val == 1) {
					$checked=" checked";
				}
				else {
					$checked="";
				}
				// Work around BUG with "checked/>"
				// So we just say "checked></input>"
				$buf .= "     <input class='formcheckbox' type=\"checkbox\" name=".
				"\"".$name."\"".$checked.$input_str."></input>";
				break;

			case 'ipaddress':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					$iparr="";
					$iparr=explode(".",$cur_val);
					if (count($iparr) == 4) {
						$ip_a=(integer)$iparr[0];
						$ip_b=(integer)$iparr[1];
						$ip_c=(integer)$iparr[2];
						$ip_d=(integer)$iparr[3];
					}
				}
				$buf .= <<<EOF
<input type="text" name="${name}_a" size="3" maxsize="3" class='forminput' value="${ip_a}"/>.
<input type="text" name="${name}_b" size="3" maxsize="3" class='forminput' value="${ip_b}"/>.
<input type="text" name="${name}_c" size="3" maxsize="3" class='forminput' value="${ip_c}"/>.
<input type="text" name="${name}_d" size="3" maxsize="3" class='forminput' value="${ip_d}"/>
EOF;
				break;

			case 'datetime':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					if ($cur_val == "now") {
						$date_a=strftime("%m",time());
						$date_b=strftime("%d",time());
						$date_c=strftime("%Y",time());
						$date_d=strftime("%I",time());
						$date_e=strftime("%M",time());
						$cur_val=strftime("%p",time()); // This is a nasty kludge ;)
					}
					else {
						$date="";
						$date=split("[/: ]",$cur_val);
						if (count($date) == 6) {
							$date_a=(integer)$date[0];
							$date_b=(integer)$date[1];
							$date_c=(integer)$date[2];
							$date_d=(integer)$date[3];
							$date_e=(integer)$date[4];
						}
					}
				}
				else {
					$date_a="";$date_b="";$date_c="";$date_d="";$date_e="";
				}
				$buf .= <<<EOF
<input type="text" name="${name}_a" size="2" class='forminput' maxsize="2" value="${date_a}"/>/
<input type="text" name="${name}_b" size="2" class='forminput' maxsize="2" value="${date_b}"/>/
<input type="text" name="${name}_c" size="4" class='forminput' maxsize="4" value="${date_c}"/>&nbsp;
<input type="text" name="${name}_d" size="2" class='forminput' maxsize="2" value="${date_d}"/>:
<input type="text" name="${name}_e" size="2" class='forminput' maxsize="2" value="${date_e}"/>
EOF;
				if(strlen($cur_val) && stristr($cur_val,"AM")) {
					$buf .= "<select name=\"".$name."_f\"><option value=\"AM\" selected>AM</option><option value=\"PM\">PM</option></select>";
				}
				else {
					$buf .= "<select name=\"".$name."_f\"><option value=\"AM\">AM</option><option value=\"PM\" selected>PM</option></select>";
				}
				break;

			case 'date':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					if ($cur_val == "now") {
						$date_a=strftime("%m",time());
						$date_b=strftime("%d",time());
						$date_c=strftime("%Y",time());
					}
					else {
						$date="";
						$date=explode("/",$cur_val);
						if (count($date) > 2) {
							$date_a=(integer)$date[0];
							$date_b=(integer)$date[1];
							$date_c=(integer)$date[2];
						}
					}
				}
				$buf .= <<<EOF
<input type="text" name="${name}_a" size="2" class='forminput' maxsize="2" value="${date_a}"/>/
<input type="text" name="${name}_b" size="2" class='forminput' maxsize="2" value="${date_b}"/>/
<input type="text" name="${name}_c" size="4" class='forminput' maxsize="4" value="${date_c}"/>
EOF;
				break;

			case 'time':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					if ($cur_val == "now") {
						$date_a=strftime("%I",time());
						$date_b=strftime("%M",time());
						$cur_val=strftime("%p",time()); // Nasty Hack :/
					}
					else {
						$date="";
						$date=split("[: ]",$cur_val);
						if (count($date) > 1) {
							if(isset($date[0])) $date_a=(integer)$date[0];
							if(isset($date[1])) $date_b=(integer)$date[1];
						}
					}
				}
				if(!(isset($date_a))) $date_a="";
				if(!(isset($date_b))) $date_b="";
				$buf .= <<<EOF
<input type="text" name="${name}_a" size="2" class='forminput' maxsize="2" value="${date_a}"/>:
<input type="text" name="${name}_b" size="2" class='forminput' maxsize="2" value="${date_b}"/>
EOF;
				if(strlen($cur_val) && stristr($cur_val,"AM")) {
					$buf .= "<select name=\"".$name."_c\"><option value=\"AM\" selected>AM</option><option value=\"PM\">PM</option></select>";
				}
				else {
					$buf .= "<select name=\"".$name."_c\"><option value=\"AM\">AM</option><option value=\"PM\" selected>PM</option></select>";
				}
				break;

			case 'money':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					$date="";
					if (strstr($cur_val,"\$")) {
						str_replace("\$"," ",$cur_val);
						$tmp=trim($cur_val);
						$cur_val=$tmp;
					}
					$date=explode(".",$cur_val);
					$date_a=(integer)$date[0];
					$date_b=sprintf("%02d",(integer)$date[1]);
				}
				$buf .= <<<EOF
$<input type="text" name="${name}_a" size="4" class='forminput' value="${date_a}"/>.
<input type="text" name="${name}_b" size="2" class='forminput' maxsize="2" value="${date_b}"/>
EOF;
				break;

			case 'percent':
				$cur_val=$this->get_var($name);
				if (strlen($cur_val)) {
					$date="";
					if (strstr($cur_val,"\%")) {
						str_replace("\%"," ",$cur_val);
						$tmp=trim($cur_val);
						$cur_val=$tmp;
					}
					$nums=explode(".",$cur_val);
					if(isset($nums[0])) $numa=(integer)$nums[0];
					if(isset($nums[1])) $numb=(integer)$nums[1];
				}
				if (!(isset($numa))) $numa="0";
				if (!(isset($numb))) $numb="0";
				$buf .= <<<EOF
<input type="text" name="${name}_a" size="4" class='forminput' value="$numa"/>.
<input type="text" name="${name}_b" size="2" class='forminput' maxsize="2" value="$numb"/>%
EOF;
				break;

			default:
				$buf .= "<h1> Unknown type: '$type' </h1>\n";
		
		}
		$buf .= "\n    </td>\n";
		if ($this->row_tmpnum == $max_cols) {
			$buf .= "   </tr>\n";
			$this->row_tmpnum=0;
		}
		return $buf;
	}

	function get_tr_class() {
		if ($this->row_class_toggle == 0) {
			$this->row_class_toggle=1;
			return "formtoggle1";
		}
		else {
			$this->row_class_toggle=0;
			return "formtoggle2";
		}
	}

	function set_default($name,$value){
		$this->defaults[$name]=$value;
	}

	function set_defaults($arr) {
		if (!(is_array($arr))) {
			return -1;
		}
		else {
			while (list($key,$value)=each($arr)) {
				$this->set_default($key,$value);
			}
		}
	}


	function get_var($string) {
		$ret="";

		if (isset($this->defaults[$string])) {
			$ret=$this->defaults[$string];
		}
		else if (isset($_SESSION[$string])) {
			$ret=$_SESSION[$string];
		}
		else if (isset($_COOKIE[$string])) {
			$ret=$_COOKIE[$string];
		}
		else if (isset($_POST[$string])) {
			$ret=$_POST[$string];
		}
		else if (isset($_GET[$string])) {
			$ret=$_GET[$string];
		}
		else {
			/* return ""; */
		}

		return htmlspecialchars(stripslashes($ret));
	}

	function change_action($action) {
		if (!(strlen($action))) return -1;
		$this->action=$action;
	}

	function sprint_form(){
		$enctype=$this->enctype;
		$method=$this->method;
		$action=$this->action;

		$table_extra=$this->table_extra;
		$form_extra=$this->form_extra;

		$this->merge_prepend();

		if (strlen($this->form_css_class)) {
			$fclass=" class=\"".$this->form_css_class."\"";
		}
		if (strlen($this->table_css_class)) {
			$tclass=" class=\"".$this->table_css_class."\"";
		}
		$this->outbuf .= <<<EOF

 <form action="$action" method="$method" enctype="$enctype"$fclass$form_extra>
  <table border="0" align="$this->form_align" cellspacing="0" cellpadding="2"$tclass$table_extra>

EOF;


		for ($j=0 ; $j < count($this->inputs) ; $j++) { // Rows
			$j2=0;
			for ($j1=0; $j1 < count($this->inputs[$j]) ; $j1++) { // Cols
				if ($this->inputs[$j][$j1] == NULL) continue;
				++$j2;
			}
			if ($j2 > $this->max_cols) {
				$this->max_cols=$j2;
			}
		}
		for ($j=0 ; $j < count($this->inputs) ; $j++) { // Rows
			for ($j1=0; $j1 < count($this->inputs[$j]) ; $j1++) { // Cols
				$cols=count($this->inputs[$j]);
				$max_cols=$this->max_cols;

				$this->outbuf .= $this->get_input_html($this->inputs[$j][$j1],$cols,
				$max_cols);
			}
		}
		if (! $this->NORESET) {
			$this->outbuf .= $this->get_submit();
		}
		$this->outbuf .= "  </table>\n";

		if (is_array($this->hidden)) {
			@reset($this->hidden);
			while (list($key,$value)=@each($this->hidden)) {
				$this->outbuf .= <<<EOF
  <input type="hidden" name="$key" value="$value" />

EOF;
			}
		}

		$this->outbuf .= <<<EOF
 </form>

EOF;
		$ret=$this->outbuf;
		$this->outbuf="";

		return $ret;
	}

	function print_form() {
		print $this->sprint_form();
	}

	function get_submit() {
		$max=$this->max_cols;
		$style=$this->get_tr_class();

		return "
   <tr class='".$style."'>
    <td colspan=\"".$max."\" align=\"center\">
     <div align=\"center\">
      <input type=\"submit\" value=\"Submit\" name=\"Submit\" class='formsubmit'>
      <input type=\"reset\" value=\"Reset\" name=\"Reset\" class='formreset'>
    </div>
   </td>
  </tr>\n";
	}

	function print_error() {
		global $PHPLIB;

		$error_str1=$this->error_str1;
		$error_str2=$this->error_str2;
		$base=$PHPLIB["uri_base"];
		$warnimage=$this->warnimage;

		$this->outbuf .= <<<EOF
<table align="center" class='formerrormsg'>
 <tr>
  <td width="10%"><img src="$base/$warnimage" alt="error"> </td>
  <td width="90%">
   <strong> $error_str1

EOF;

		@reset($this->validate_errors);
		while (list($key,$value)=each($this->validate_errors)) {
			$this->outbuf .= "   <br/>$value\n";
		}

		$this->outbuf .= <<<EOF
   <br/> $error_str2 </strong>
  </td>
 </tr>
</table>

EOF;
	}

	function merge_prepend() {
		if (!($this->prepend_done)) {
			if (count($this->prepend)) {
				$tmparr=array();
				$tmparr=array_merge($this->prepend, $this->inputs);
				$this->inputs=$tmparr;
				unset($tmparr);
				$this->prepend_done=1;
			}
		}
	}

	function validate() {
		$this->merge_prepend();

		$error=0;
		for ($j=0 ; $j < count($this->inputs) ; $j++) {
			if (!(isset($this->inputs[$j]))||(!(is_array($this->inputs[$j])))) continue;
			for ($j1=0; $j1 < count ($this->inputs[$j]); $j1++) {
				if (!(isset($this->inputs[$j][$j1]))||(!(is_array($this->inputs[$j][$j1])))) continue;
				if (isset($this->inputs[$j][$j1]["name"])) $name=$this->inputs[$j][$j1]["name"];
				$value=$this->get_var($name);
				$extra=$this->inputs[$j][$j1]["extra"];
				$error_msg=$this->validate_type($value,$extra,$name);
				if (strlen($error_msg)) {
					$this->invalid_arr[$name]=1;
					$this->validate_errors[$name]=$error_msg;
					$error++;
				}
			}
		}
		if ($error > 0) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}

	function validate_type($data,$type,$name="Unknown") {
		$error=$num=0;
		$errormsg="";

		$tmparr=explode(",",$type);
		if(isset($tmparr[0])) {
			$type=$tmparr[0];
		} else {
			$type="default";
		}
		if(isset($tmparr[1])) {
			$min=$tmparr[1];
		} else {
			$min="";
		}
		if(isset($tmparr[2])) {
			$max=$tmparr[2];
		} else {
			$max="";
		}


		switch ($type) {
			case "str":
			case "string":
				if (strlen($data) < $min) {
					$error += 1;
					$errormsg .= $name ." is too short";
				}
				if (strlen($data) > $max) {
					$error += 1;
					$errormsg .= $name ." is too long";
				}
				break;
			case "integer":
			case "number":
			case "int":
				for ($j=0 ; $j < strlen($data) ; $j++) {
					if (is_numeric($data[$j])) {
						$num++;
					}
				}
				if ($num < $min) {
					$error += 1;
					$errormsg .= $name ." is too short";
				}
				if ($num > $max) {
					$error += 1;
					$errormsg .= $str_desc ." is too long";
				}
				break;
			case "email":
				$dom_flg=0;
				for ($j=0; $j < strlen($data) ; $j++) {
					if ($data[$j] == "@") {
						$dom_flg=1;
						$j++;
					}
					if ($dom_flg) {
						$domain .= $data[$j];
					}
					else {
						$user .= $data[$j];
					}
				}
				if (strlen($user) < 1) {
					$error += 1;
				}
				if (strlen($domain) < 5) {
					$error += 1;
				}
				if ($error) {
					$errormsg .= "Email address is invalid";
				}
				break;
			default:
				break;
		}
		if ($error) {
			return $errormsg;
		}
	}

} // formclass

} // double include protect
