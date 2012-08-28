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

#include <errno.h>

#include <settings.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc.h>
#include <unilib/xipc_private.h>

/* XXX this needs to be written more clearly */

static union {
	struct message_s *m;
	void *ptr;
	uint8_t *hdr;
} m_u[MAX_CONNS][MAX_MSGS];

static int setup_mptrs(int /* sock */);

static uint8_t *msg_buf[MAX_CONNS], *save_buf[MAX_CONNS];
static size_t m_off[MAX_CONNS], m_max[MAX_CONNS];
static ssize_t readsize[MAX_CONNS];
static size_t save_size[MAX_CONNS], ureadsize[MAX_CONNS];

int ipc_init(void) {
	int j=0;

	for (j=0; j < MAX_CONNS; j++) {
		msg_buf[j]=NULL; save_buf[j]=NULL;
		m_off[j]=0; m_max[j]=0;
		readsize[j]=-1;
		save_size[j]=0; ureadsize[j]=0;
	}

	return 1;
}

static void reset_messages(int sock) {
	int j=0;

	if (sock < 0 || sock >= MAX_CONNS) {
		PANIC("socket out of range [%d]", sock);
	}

	for (j=0; j < MAX_MSGS; j++) {
		m_u[sock][j].ptr=NULL;
	}

	if (msg_buf[sock] != NULL) {
		xfree(msg_buf[sock]);
		msg_buf[sock]=NULL;
	}

	ureadsize[sock]=0; readsize[sock]=0;
	return;
}


int recv_messages(int sock) {

	DBG(M_IPC, "recv_messages on socket %d", sock);

	if (sock < 0 || sock >= MAX_CONNS) {
		PANIC("socket out of range [%d]", sock);
	}

	reset_messages(sock);

	msg_buf[sock]=(uint8_t *)xmalloc(IPC_DSIZE);
	memset(msg_buf[sock], 0, IPC_DSIZE);

	assert(save_size[sock] <= MAX_SLACKSIZE);

	if (save_size[sock]) {
		if (save_buf[sock] == NULL) {
			PANIC("save_size is not zero but save_buf is null");
		}

		DBG(M_IPC, "saved data in buffer, saving it in beginning of read buffer");
		memcpy(msg_buf[sock], save_buf[sock], save_size[sock]);
		xfree(save_buf[sock]);
	}

again:
	readsize[sock]=read(
		sock,
		&msg_buf[sock][save_size[sock]],
		IPC_DSIZE - save_size[sock]
	);

	if (readsize[sock] < 0 && errno == EINTR) {
		goto again;
	}

	if (readsize[sock] < 0) {
		msg_buf[sock]=NULL;
		ERR("read fails: %s", strerror(errno));
		return -1;
	}

	ureadsize[sock]=(size_t)readsize[sock];
	ureadsize[sock] += save_size[sock];
	save_size[sock]=0;

	if (ureadsize[sock] == 0) {
		/* EOF from peer, even with buffer */
		return 0;
	}

	if (ureadsize[sock] < sizeof(ipc_msghdr_t)) {
		ERR("undersized ipc message, only " SSTFMT " bytes [min required " STFMT "]",
			ureadsize[sock], sizeof(ipc_msghdr_t)
		);
		return -1;
	}

	DBG(M_IPC, "read %u bytes of data from fd %d", (unsigned int)ureadsize[sock], sock);

	/* now setup the m_u strucure to point to the messages */
	setup_mptrs(sock);

	m_off[sock]=0;

	return 1;
}

/*
 * returns 1 (more to read) or 0 (done reading), or -1 for error
 * if a sender sends 2 messages, then the last will be read first,
 * and the second to last next, etc
 */

int get_message(int sock, uint8_t *type, uint8_t *status, uint8_t **data, size_t *data_len) {

	assert(data != NULL && type != NULL && status != NULL && data_len != NULL);
	*data=NULL; *type=0; *data_len=0;

	if (sock < 0 || sock >= MAX_CONNS) {
		PANIC("socket out of range [%d]", sock);
	}

	assert(m_off[sock] < (MAX_MSGS - 1));

	if (m_u[sock][m_off[sock]].ptr == NULL) {
		DBG(M_IPC, "get_message: returning 0 end of messages");
		*type=0;
		*status=0;
		*data=NULL;
		*data_len=0;
		return 0;
	}


	DBG(M_IPC,	"get_message: message type %u status %u data_len " STFMT
			" and m_off " STFMT " out of m_max " STFMT,
			m_u[sock][m_off[sock]].m->hdr.type,
			m_u[sock][m_off[sock]].m->hdr.status,
			m_u[sock][m_off[sock]].m->hdr.len,
			m_off[sock],
			m_max[sock]
	);

	if (m_u[sock][m_off[sock]].m->hdr.header != IPC_MAGIC_HEADER) {
		PANIC("wrong magic number for IPC header"); /* obviously we should choose our friends more closely */
	}
	*type=m_u[sock][m_off[sock]].m->hdr.type;
	*status=m_u[sock][m_off[sock]].m->hdr.status;
	*data=&m_u[sock][m_off[sock]].m->data[0];
	*data_len=m_u[sock][m_off[sock]].m->hdr.len;
	++m_off[sock];

	return 1;
}

int get_singlemessage(int sock, uint8_t *type, uint8_t *status, uint8_t **data, size_t *data_len) {

	assert(data != NULL && type != NULL && status != NULL && data_len != NULL);
	*data=NULL; *type=0; *data_len=0;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("socket out of range [%d]", sock);

	if (recv_messages(sock) < 1) {
		return -1;
	}

	if (m_max[sock] > 1) {
		PANIC("too many messages m_max is " STFMT, m_max[sock]);
	}

	if (m_u[sock][m_off[sock]].ptr == NULL) {
		PANIC("null message");
	}

	DBG(M_IPC,	"get_message: message type %s status %u data_len " STFMT
			" and m_off " STFMT " out of m_max " STFMT,
			strmsgtype(m_u[sock][0].m->hdr.type),
			m_u[sock][0].m->hdr.status,
			m_u[sock][0].m->hdr.len,
			m_off[sock],
			m_max[sock]
	);

	*type=m_u[sock][0].m->hdr.type;
	*status=m_u[sock][0].m->hdr.status;
	*data=&m_u[sock][0].m->data[0];
	*data_len=m_u[sock][0].m->hdr.len;

	return 1;
}

static int setup_mptrs(int sock) {
	size_t mptr_off=0, gmptr_off=0;

	if (sock < 0 || sock >= MAX_CONNS) {
		PANIC("socket out of range [%d]", sock);
	}

	if (ureadsize[sock] < sizeof(ipc_msghdr_t)) {
		PANIC("setup mptrs called with too small read buffer " SSTFMT " bytes", ureadsize[sock]);
	}

	for (m_off[sock]=0, mptr_off=0, m_max[sock]=0; mptr_off < ureadsize[sock]; m_off[sock]++) {

		if (m_off[sock] >= MAX_MSGS) {
			PANIC("too many messages in ipc read " STFMT, m_off[sock]);
		}

		if (mptr_off + sizeof(ipc_msghdr_t) > ureadsize[sock]) {
			save_size[sock]=ureadsize[sock] - mptr_off;
			save_buf[sock]=(uint8_t *)xmalloc(save_size[sock]);
			memcpy(save_buf[sock], &msg_buf[sock][mptr_off], save_size[sock]);
			m_u[sock][m_off[sock]].ptr=NULL;
			break;
		}
		m_u[sock][m_off[sock]].hdr=&msg_buf[sock][mptr_off];

		if (m_u[sock][m_off[sock]].m->hdr.header != IPC_MAGIC_HEADER) {
			PANIC("ipc message is damaged, wrong magic number `%08x' m_off=" STFMT " mptr_off=" STFMT,
				m_u[sock][m_off[sock]].m->hdr.header,
				m_off[sock],
				mptr_off
			);
		}
		DBG(M_IPC, "got IPC Message header type %u[%s] status %u length " STFMT,
			m_u[sock][m_off[sock]].m->hdr.type,
			strmsgtype(m_u[sock][m_off[sock]].m->hdr.type),
			m_u[sock][m_off[sock]].m->hdr.status,
			m_u[sock][m_off[sock]].m->hdr.len
		);
		gmptr_off=mptr_off;
		mptr_off += (m_u[sock][m_off[sock]].m->hdr.len + sizeof(ipc_msghdr_t)); /* INC */
	} /* for mptr_off < ureadsize */

	/* now figure out how many (if any) bytes were left trailing at the end, and save them */
	if (mptr_off > ureadsize[sock]) {
		save_size[sock]=ureadsize[sock] - gmptr_off;
		if (save_size[sock] > MAX_SLACKSIZE) PANIC("saved data is too big");

		save_buf[sock]=(uint8_t *)xmalloc(save_size[sock]);
		memcpy(save_buf[sock], &msg_buf[sock][gmptr_off], save_size[sock]);
		/* the message we are on is incomplete, remove it from the recv area */
		m_off[sock]--;
		m_u[sock][m_off[sock]].ptr=NULL;
	}

	if (m_off[sock] == 0) {
		ERR("wtf");
		return -1;
	}

	assert(m_off[sock] > 0);

	m_max[sock]=(m_off[sock] - 1);
	m_off[sock]=0;

	return 1;
}


int send_message(int sock, int type, int status, const uint8_t *data, size_t data_len) {
	union {
		struct message_s *m;
		void *ptr;
	} sm_u;
	ssize_t ret=0;
	struct message_s m;

	if (sock < 0 || sock >= MAX_CONNS) PANIC("socket out of range [%d]", sock);

	memset(&m, 0, sizeof(m));
	sm_u.m=&m;

	if (data_len > (IPC_DSIZE - sizeof(ipc_msghdr_t))) {
		PANIC("attempt to send oversized packet of length " STFMT " from IPC", data_len);
	}

	if (type < 0 || type > 0xFF) {
		ERR("message type out of range `%d'", type);
		return -1;
	}
	sm_u.m->hdr.type=(uint8_t)type;

	if (status < 0 || status > 0xFF) {
		ERR("message status out of range `%d'", status);
		return -1;
	}
	sm_u.m->hdr.status=(uint8_t)status;

	sm_u.m->hdr.len=data_len;
	sm_u.m->hdr.header=IPC_MAGIC_HEADER;

	DBG(M_IPC, "sending ipc message type %d[%s] status %d len " STFMT " to fd %d",
		type,
		strmsgtype(type),
		status,
		data_len,
		sock
	);

	if (data_len > 0) {
		memcpy(sm_u.m->data, data, data_len);
	}

again:
	ret=write(sock, sm_u.ptr, (sizeof(ipc_msghdr_t) + data_len));
	if (ret < 0 && errno == EINTR) {
		goto again;
	}

	/* XXX
	 * in practice this doesnt generally fail (partial writes mostly),
	 * but we should check for it and retry
	 */

	if (ret > 0 && (size_t)ret != sizeof(ipc_msghdr_t) + data_len) {
		ERR("partial write, this is likely going to cause problems");
	}
	else if (ret < 1) {
		ERR("write failed somehow, this is likely going to cause problems");
	}

	return ret;
}

struct msg_ntbl {
	int type;
	char hr[32];
};

static struct msg_ntbl m_tbl[]={
/*					|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0 */
{MSG_ERROR,				"Error"				  },
{MSG_VERSIONREQ,			"VersionRequest"		  },
{MSG_VERSIONREPL,			"VersionReply"			  },
{MSG_QUIT,				"Quit"				  },
{MSG_WORKUNIT,				"Workunit"			  },
{MSG_WORKDONE,				"Workdone"			  },
{MSG_OUTPUT,				"Output"			  },
{MSG_READY,				"Ready"				  },
{MSG_ACK,				"Ack"				  },
{MSG_IDENT,				"Ident"				  },
{MSG_IDENTSENDER,			"IdentSender"			  },
{MSG_IDENTLISTENER,			"IdentListener"			  },
{MSG_NOP,				"Nop"				  },
{MSG_TERMINATE,				"Terminate"			  },
{-1,					"error"				  }
};

char *strmsgtype(int msgtype) {
	static char sbuf[32];
	uint32_t j=0;

	CLEAR(sbuf);
	for (j=0; m_tbl[j].type != -1; j++) {
		if (m_tbl[j].type == msgtype) {
			sprintf(sbuf, "%s", m_tbl[j].hr);
			return &sbuf[0];
		}
	}

	sprintf(sbuf, "UNKNOWN [%d]", msgtype);
	return &sbuf[0];
}

#undef IPC_DSIZE
#undef IPC_MAGIC_HEADER
#undef MAX_MSGS
#undef MAX_SLACKSIZE
