//
// Created by mike on 8/3/26.
//

#ifndef UWCPFLOODING_H
#define UWCPFLOODING_H


#include "uwcpflooding-hdr.h"

#include <timer-handler.h>
#include <uwcbr-module.h>
#include <uwip-clmsg.h>
#include <uwip-module.h>

#include "mphy.h"
#include "packet.h"
#include <module.h>
#include <tclcl.h>

#include <cmath>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <rng.h>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include <uwphysical.h>
#include <clmsg-stats.h>
#include <clmsg-discovery.h>
#include <clmsg-stats.h>
#include <uwstats-utilities.h>

class UwCPFloodingHandler;
/**
 * UwCPFlooding class is used to represent the routing layer of a node.
 */
class UwCPFlooding : public Module
{

public:
	friend class UwCPFloodingHandler;

    /**
     * Constructor of UwCPFlooding class.
     */
    UwCPFlooding();

    /**
     * Destructor of UwCPFlooding class.
     */
    virtual ~UwCPFlooding();

protected:
    /*****************************
     |     Internal Functions    |
     *****************************/
    /**
     * TCL command interpreter. It implements the following OTcl methods:
     *
     * @param argc Number of arguments in <i>argv</i>.
     * @param argv Array of strings which are the command parameters (Note that
     * <i>argv[0]</i> is the name of the object).
     * @return TCL_OK or TCL_ERROR whether the command has been dispatched
     * successfully or not.
     *
     */
    virtual int command(int, const char *const *);

    /**
     * Performs the reception of packets from upper and lower layers.
     *
     * @param Packet* Pointer to the packet will be received.
     */
    virtual void recv(Packet *);

    /**
     * Cross-Layer messages synchronous interpreter.
     *
     * @param ClMessage* an instance of ClMessage that represent the message
     * received
     * @return <i>0</i> if successful.
     */
    virtual int recvSyncClMsg(ClMessage *);

    /**
     * Cross-Layer messages asynchronous interpreter. Used to retrieve the IP
     * of the current node from the IP module.
     *
     * @param ClMessage* an instance of ClMessage that represent the message
     * received and used for the answer.
     * @return <i>0</i> if successful.
     */
    virtual int recvAsyncClMsg(ClMessage *);

    /**
     * Returns a nsaddr_t address from an IP written as a string in the form
     * "x.x.x.x".
     *
     * @param char* IP in string form
     * @return nsaddr_t that contains the IP converted from the input string
     */
    static nsaddr_t str2addr(const char *);

    /**
     * Return a string with an IP in the classic form "x.x.x.x" converting an
     * ns2 nsaddr_t address.
     *
     * @param nsaddr_t& ns2 address
     * @return String that contains a printable IP in the classic form "x.x.x.x"
     */
    static std::string printIP(const nsaddr_t &);

    /**
     * Get the value of the TTL for a packet.
     *
     * @param p pointer to the packet for which the ttl has to be computed.
     * @return the ttl for that packet
     */
    uint8_t getTTL(Packet *p) const;

private:
    // Variables
	double rx_power; // Мощность полезного сигнала
	double noise;    // Шум
	double interf;   // Помехи/Интерференция
	double sinr;     // SINR
	double ber;      // BER
	double per;      // PER
	bool   is_err;   // Была ли ошибка приема

    uint8_t ipAddr_;
    long packets_forwarded_; /**< Number of packets forwarded by this module. */
    std::ostringstream osstream_; /**< Used to convert to string. */

	double te_;  /**< Transmission Efficiency */
	double time_window = 5000; /**< Time window */

	/**
	* Stats pointer, dynamically allocated by method setStats
	**/
	Stats* stats_ptr;

	typedef struct {
		double nd;
		double timestamp;
		uint8_t prev_prev_hop_;
		bool is_relayed;
		UwCPFloodingHandler* timer;
		std::map<uint8_t, double> coverage_map;
		std::map<uint8_t, double> coverage_timestamps;
	} packet_state;

	typedef std::map<uint16_t, packet_state> map_packets_state;
	typedef std::map<uint8_t, map_packets_state>
		map_all_packets; /**< Typedef for a map of the packet
							  (saddr, map_packets_state). */

	map_all_packets my_all_packets_; /**< Map of all packets (forwarded + pending). */

	std::set<uint8_t> U_u;                       // Множество непокрытых соседей U(u)
	std::map<uint8_t, double> link_quality_neighbors; // L(u,k)
	std::map<std::pair<uint8_t, uint8_t>, std::set<uint16_t>> neighbors; // Bvu, Bvk

    /**
     * Copy constructor declared as private. It is not possible to create a new
     * UwCPFlooding object passing to its constructor another UwCPFlooding object.
     *
     * @param UwCPFlooding& UwCPFlooding object.
     */
    UwCPFlooding(const UwCPFlooding &);

    /**
     * Assignment operator declared as private.
     */
    UwCPFlooding &operator=(const UwCPFlooding &);

	/**
	 * Forward a packet after timer expiration.
	 *
	 * @param p Packet to forward.
	 */
	void doForward(Packet *p);
};

class UwCPFloodingHandler : public TimerHandler
{
public:
    UwCPFloodingHandler(UwCPFlooding* m, Packet *p);
    virtual ~UwCPFloodingHandler();
	Packet* pkt() const;

protected:
    void expire(Event *e);

private:
    UwCPFlooding *module_;
    Packet *pkt_;
};

#endif // UWCPFLOODING_H