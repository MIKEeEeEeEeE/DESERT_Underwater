//
// Created by mike on 8/3/26.
//

#ifndef UWCPDFLOODING_HDR_H
#define UWCPDFLOODING_HDR_H

#include <packet.h>

#define HDR_UWCPDFLOODING(p) (hdr_uwcpdflooding::access(p))
#define HDR_UWCPDFLOODING_NOTIFICATION(p) (hdr_uwcpdflooding_notification::access(p))

extern packet_t PT_UWCPDFLOODING;
extern packet_t PT_UWCPDFLOODING_NOTIFICATION;


/**
 * <i>hdr_uwdflooding</i> describes packets used by <i>UWDFLOODING</i>.
 */
typedef struct hdr_uwcpdflooding {

	uint8_t ttl_; /**< Time to live of the packet. */
	uint8_t hop_; /**< Count-up of hops. */
	nsaddr_t prev_prev_hop_{};
	static int offset_; /**< Required by the PacketHeaderManager. */

	/**
	 * Reference to the ttl_ variable.
	 */
	inline uint8_t &
	ttl()
	{
		return ttl_;
	}

	/**
	 * Reference to the hop_ variable.
	 */
	inline uint8_t &
	hop()
	{
		return hop_;
	}

	/**
	 * Reference to the offset_ variable.
	 */
	inline static int &
	offset()
	{
		return offset_;
	}

	inline nsaddr_t &
	prev_prev_hop()
	{
		return prev_prev_hop_;
	}

	inline static struct hdr_uwcpdflooding *
	access(const Packet *p)
	{
		return (struct hdr_uwcpdflooding *) p->access(offset_);
	}
} hdr_uwcpdflooding;

#endif
