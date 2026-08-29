//
// Created by mike on 8/3/26.
//

#ifndef UWCPFLOODING_HDR_H
#define UWCPFLOODING_HDR_H

#include <packet.h>

#define HDR_UWCPFLOODING(p) (hdr_uwcpflooding::access(p))
#define HDR_UWCPFLOODING_NOTIFICATION(p) (hdr_uwcpflooding_notification::access(p))

extern packet_t PT_UWCPFLOODING;
extern packet_t PT_UWCPFLOODING_NOTIFICATION;


/**
 * <i>hdr_uwcpflooding</i> describes packets used by <i>UWCPFLOODING</i>.
 */
typedef struct hdr_uwcpflooding {
	
	uint8_t prev_prev_hop_;
	static int offset_; /**< Required by the PacketHeaderManager. */

	/**
	 * Reference to the offset_ variable.
	 */
	inline static int &
	offset()
	{
		return offset_;
	}

	inline static struct hdr_uwcpflooding *
	access(const Packet *p)
	{
		return (struct hdr_uwcpflooding *) p->access(offset_);
	}
} hdr_uwcpflooding;

#endif
