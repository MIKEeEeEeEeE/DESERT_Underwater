//
// Created by mike on 8/3/26.
//

#ifndef UWDFLOODING_H
#define UWDFLOODING_H

#define TTL_EQUALS_TO_ZERO \
    "TEZ" /**< Reason for a drop in a <i>UWDFLOODING</i> module. */

#include "uwdflooding-hdr.h"

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

class UwdfloodingHandler;
/**
 * UwFlooding class is used to represent the routing layer of a node.
 */
class UwDflooding : public Module
{

public:
	friend class UwdfloodingHandler;

    /**
     * Constructor of UwFlooding class.
     */
    UwDflooding();

    /**
     * Destructor of UwFlooding class.
     */
    virtual ~UwDflooding();

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
     * Writes in the Path Trace file the path contained in the Packet
     *
     * @param Packet to analyze.
     * @param action String describing the action performed.
     */
    virtual void writePathInTrace(const Packet *, const std::string &);

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

    /**
     * Forward a packet after timer expiration.
     *
     * @param p Packet to forward.
     */
    void doForward(Packet *p);

private:
    // Variables

    uint8_t ipAddr_;
    int ttl_; /**< Time to live of the <i>UWDFLOODING</i> packets. */
    int optimize_; /**< Flag used to enable the mechanism to drop packets
                      processed twice. */
    long packets_forwarded_; /**< Number of packets forwarded by this module. */
    bool trace_path_; /**< Flag used to enable or disable the path trace file
                         for nodes. */
    char *trace_file_path_name_; /**< Name of the trace file that contains
                                    the list of paths of the data packets
                                    received. */
    std::ofstream trace_file_path_; /**< Ofstream used to write the path trace file
                                  in the disk. */
    std::ostringstream osstream_; /**< Used to convert to string. */
	
    double t_max_; /**< Maximum random delay for optimized forwarding. */
    double t_min_; /**< Minimum random delay for optimized forwarding. */
    double n_dupl_; /**< Number of duplicates threshold. */
	double t_dupl_; /**< Time window for duplicates */

    typedef struct {
        uint8_t hop;
        double nd;
    	double timestamp;
        bool is_relayed;
        UwdfloodingHandler* timer;
    } packet_state;

    typedef std::map<uint16_t, packet_state> map_packets_state;
    typedef std::map<uint8_t, map_packets_state>
        map_all_packets; /**< Typedef for a map of the packet
                              (saddr, map_packets_state). */

    map_all_packets my_all_packets_; /**< Map of all packets (forwarded + pending). */

    std::map<uint16_t, uint8_t>
            ttl_traffic_map; /**< Map with ttl per traffic. */

    /**
     * Copy constructor declared as private. It is not possible to create a new
     * UwDflooding object passing to its constructor another UwDflooding object.
     *
     * @param UwDflooding& UwDflooding object.
     */
    UwDflooding(const UwDflooding &);

    /**
     * Assignment operator declared as private.
     */
    UwDflooding &operator=(const UwDflooding &);
};

class UwdfloodingHandler : public TimerHandler
{
public:
    UwdfloodingHandler(UwDflooding* m, Packet *p);
    virtual ~UwdfloodingHandler();
	Packet* pkt() const;

protected:
    void expire(Event *e);

private:
    UwDflooding *module_;
    Packet *pkt_;
};

#endif // UWDFLOODING_H