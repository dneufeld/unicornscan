/**********************************************************************
 * Copyright (C) 2004-2006 (Jack Louis) <jack@rapturesecurity.org>    *
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
#include <config.h>

#include <settings.h>

char *stroptions(uint16_t options) {
	static char optstr[512];

	snprintf(optstr, sizeof(optstr) -1,
			"process errors %s, immediate %s, listen drone %s, send drone %s, output drone %s, "
			"do connect %s, report quiet %s, ignore root %s, do dns %s, do translate %s, "
			"process duplicates %s",
		GET_PROCERRORS()	? "yes" : "no",
		GET_IMMEDIATE()		? "yes" : "no",
		GET_LISTENDRONE()	? "yes" : "no",
		GET_SENDDRONE()		? "yes" : "no",
		GET_OUTPUTDRONE()	? "yes" : "no",
		GET_DOCONNECT()		? "yes" : "no",
		GET_REPORTQUIET()	? "yes" : "no",
		GET_IGNROOT()		? "yes" : "no",
		GET_DODNS()		? "yes" : "no",
		GET_DOTRANS()		? "yes" : "no",
		GET_PROCDUPS()		? "yes" : "no"
	);

	return optstr;
}

char *strsendopts(uint16_t options) {
	static char optstr[512];

	snprintf(optstr, sizeof(optstr) -1,
			"shuffle ports %s, source override %s, def payload %s, broken trans crc %s, "
			"broken network crc %s, sender interuptable %s",
		GET_SHUFFLE()		? "yes" : "no",
		GET_OVERRIDE()		? "yes" : "no",
		GET_DEFAULT()		? "yes" : "no",
		GET_BROKENTRANS()	? "yes" : "no",
		GET_BROKENNET()		? "yes" : "no",
		GET_SENDERINTR()	? "yes" : "no"
	);

	return optstr;
}

char *strrecvopts(uint16_t options) {
	static char optstr[512];

	snprintf(optstr, sizeof(optstr) -1,
			"watch errors %s, promisc mode %s, do connect %s, ignore rseq %s, ignore seq %s, sniff %s",
		GET_WATCHERRORS()	? "yes" : "no",
		GET_PROMISC()		? "yes" : "no",
		GET_LDOCONNECT()	? "yes" : "no",
		GET_IGNORERSEQ()	? "yes" : "no",
		GET_IGNORESEQ()		? "yes" : "no",
		GET_SNIFF()		? "yes" : "no"
	);

	return optstr;
}
