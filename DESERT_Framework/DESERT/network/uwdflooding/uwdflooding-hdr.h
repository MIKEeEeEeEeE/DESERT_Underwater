//
// Created by mike on 8/3/26.
//

#ifndef UWDFLOODING_HDR_H
#define UWDFLOODING_HDR_H

#include <packet.h>

#define HDR_UWDFLOODING(p) (hdr_uwdflooding::access(p))
#define HDR_UWDFLOODING_NOTIFICATION(p) (hdr_uwdflooding_notification::access(p))

extern packet_t PT_UWDFLOODING;
extern packet_t PT_UWDFLOODING_NOTIFICATION;


/**
 * <i>hdr_uwdflooding</i> describes packets used by <i>UWDFLOODING</i>.
 */
typedef struct hdr_uwdflooding {

	uint8_t ttl_; /**< Time to live of the packet. */
	uint8_t hop_; /**< Count-up of hops. */
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

	inline static struct hdr_uwdflooding *
	access(const Packet *p)
	{
		return (struct hdr_uwdflooding *) p->access(offset_);
	}
} hdr_uwdflooding;

#endif
