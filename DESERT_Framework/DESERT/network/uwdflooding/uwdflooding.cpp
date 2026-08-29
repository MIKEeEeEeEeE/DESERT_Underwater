//
// Copyright (c) 2017 Regents of the SIGNET lab, University of Padova.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the University of Padova (SIGNET lab) nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "uwdflooding.h"

#include "uwdflooding-hdr.h"

#define uniform(a, b)  ((RNG::defaultrng()->uniform_double() * ((b) - (a)) + (a)))

extern packet_t PT_UWDFLOODING;
extern packet_t PT_UWDFLOODING_NOTIFICATION;

int hdr_uwdflooding::offset_ = 0; /**< Offset used to access in
                                     <i>hdr_uwdflooding</i> packets header. */

/**
 * Adds the module for UwDflooding in ns2.
 */
static class UwDfloodingModuleClass : public TclClass
{
public:
    UwDfloodingModuleClass()
        : TclClass("Module/UW/DFLOODING")
    {
    }

    TclObject*
    create(int, const char *const *)
    {
        return (new UwDflooding());
    }
} class_mod_uwdflooding;

/**
 * Adds the header for <i>hdr_uwdflooding</i> packets in ns2.
 */
static class UwDfloodingPktClass : public PacketHeaderClass
{
public:
    UwDfloodingPktClass()
        : PacketHeaderClass("PacketHeader/DFLOODING", sizeof(hdr_uwdflooding))
    {
        this->bind();
        bind_offset(&hdr_uwdflooding::offset_);
    }
} class_uwdflooding_pkt;

UwdfloodingHandler::UwdfloodingHandler(UwDflooding *m, Packet* p)
    : TimerHandler()
    , module_(m)
    , pkt_(p)
{
}

UwdfloodingHandler::~UwdfloodingHandler()
{
}

void
UwdfloodingHandler::expire(Event *e)
{
    module_->doForward(pkt_);
}

Packet*
UwdfloodingHandler::pkt() const
{
	return pkt_;
}

void
UwdfloodingHandler::setPacket(Packet *p)
{
	pkt_ = p;
}

UwDflooding::UwDflooding()
    : ipAddr_(0)
    , packets_forwarded_(0)
    , t_max_(0)
    , t_min_(0)
    , n_dupl_(0)
	, t_dupl_(0)
{ // Binding to TCL variables.
    bind("t_max_", &t_max_);
    bind("t_min_", &t_min_);
    bind("n_dupl_", &n_dupl_);
    bind("t_dupl_", &t_dupl_);
} /* UwDflooding::UwDflooding */

UwDflooding::~UwDflooding()
{
} /* UwDflooding::~UwDflooding */

int
UwDflooding::recvSyncClMsg(ClMessage *m)
{
    return Module::recvSyncClMsg(m);
} /* UwDflooding::recvSyncClMsg */

int
UwDflooding::recvAsyncClMsg(ClMessage *m)
{
    return Module::recvAsyncClMsg(m);
} /* UwDflooding::recvAsyncClMsg */

void
UwDflooding::doForward(Packet *p)
{
    hdr_uwdflooding *fh = HDR_UWDFLOODING(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_cmn *ch = HDR_CMN(p);
    uint8_t saddr = iph->saddr();
    uint16_t uid = ch->uid();

    map_all_packets::iterator it = my_all_packets_.find(saddr);
    if (it != my_all_packets_.end()) {
        map_packets_state::iterator it2 = it->second.find(uid);
        if (it2 != it->second.end()) {
            packet_state &st = it2->second;
            fh->hop() = st.hop + 1;
            st.is_relayed = true;
        	st.timer->setPacket(nullptr);
        	delete st.timer;
        	st.timer = nullptr;
        }
    }

    sendDown(p);
    packets_forwarded_++;
	printOnLog(Logger::LogLevel::DEBUG,
			"UWDFLOODING",
			"doForward()::Packet relayed " + std::to_string(ch->uid()) + ")");
}

int
UwDflooding::command(int argc, const char *const *argv)
{
	Tcl &tcl = Tcl::instance();

	if (argc == 2) {
		if (strcasecmp(argv[1], "getpacketsforwarded") == 0) {
			tcl.resultf("%lu", packets_forwarded_);
			return TCL_OK;
		} else if (strcasecmp(argv[1], "getfloodingheadersize") == 0) {
			tcl.resultf("%d", sizeof(hdr_uwdflooding));
			return TCL_OK;
		}
	} else if (argc == 3) {
		if (strcasecmp(argv[1], "addr") == 0) {
			ipAddr_ = static_cast<uint8_t>(atoi(argv[2]));
			if (ipAddr_ == 0) {
				fprintf(stderr, "0 is not a valid IP address");
				return TCL_ERROR;
			}
			return TCL_OK;
		}
	}
	return Module::command(argc, argv);
} /* UwDflooding::command */

void
UwDflooding::recv(Packet *p)
{
    hdr_cmn *ch = HDR_CMN(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_uwdflooding *flh = HDR_UWDFLOODING(p);

    if (!ch->error()) {

        if (ch->direction() == hdr_cmn::UP) {
        	/*
        	 * When a node receives a “Receive Notification” it will
        	 * discard any forwarding of that packet.
        	 */
        	// Cancel by timer (Notification received)
        	if (ch->ptype() == PT_UWDFLOODING_NOTIFICATION) {
        		printOnLog(Logger::LogLevel::DEBUG,
					"UWDFLOODING",
					"recv():: Notification packet received for UID: " +
						std::to_string(ch->uid()) + " from src: " +
						printIP(iph->saddr()));

        		map_all_packets::iterator it2 = my_all_packets_.find(iph->saddr());
        		if (it2 != my_all_packets_.end()) {
        			map_packets_state::iterator it3 = it2->second.find(ch->uid());
        			if (it3 != it2->second.end()) {
        				if (it3->second.timer != nullptr) {
        					it3->second.timer->force_cancel();
        					Packet::free(it3->second.timer->pkt());
        					delete it3->second.timer;
        					it3->second.timer = nullptr;
        				}
        				printOnLog(Logger::LogLevel::DEBUG,
							"UWDFLOODING",
							"recv():: Forwarding timer cancelled for UID: " +
								std::to_string(ch->uid()));
        			}
        		}
        		Packet::free(p);
        		return;
        	}

        	// Destination address not set -> drop
            if (iph->daddr() == 0) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Destination address is 0. Dropping packet.");
                Packet::free(p);
                return;
            }

        	/*
        	* The end destination will immediately (with absolute precedence)
        	* broadcast (single hop) a “Receive Notification”
        	* message containing the original packet
        	*/
        	// Packet destined to this node
            if (iph->daddr() == ipAddr_) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Packet UID: " + std::to_string(ch->uid()) +
                        " reached final destination node " + std::to_string(ipAddr_));

                // Send notification message
                Packet *notif = Packet::alloc();

                hdr_cmn *ch_ = HDR_CMN(notif);
                ch_->ptype() = PT_UWDFLOODING_NOTIFICATION;
                ch_->size() = 0;
                ch_->uid() = ch->uid();
                ch_->direction() = hdr_cmn::DOWN;
                ch_->prev_hop_ = ipAddr_;
                ch_->next_hop() = UWIP_BROADCAST;

                hdr_uwip *iph_ = HDR_UWIP(notif);
                iph_->saddr() = iph->saddr();
                iph_->daddr() = UWIP_BROADCAST;

                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Sending notification message down for UID: " +
                        std::to_string(ch->uid()));
                sendDown(notif);

                sendUp(p);
                return;
            }

            // Packet from this node (loopback) - discard
            if (iph->saddr() == ipAddr_) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Loopback packet detected from self. Dropping.");
                Packet::free(p);
                return;
            }

            // Broadcast packet
            if (iph->daddr() == UWIP_BROADCAST) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Processing broadcast packet UID: " +
                        std::to_string(ch->uid()) + " from src: " +
                        printIP(iph->saddr()));

            	// sendUp always: the destination is in broadcast.
            	ch->size() -= sizeof(hdr_uwdflooding);
            	sendUp(p->copy());

                // SendDown setup
                ch->direction() = hdr_cmn::DOWN;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;
                ch->size() += sizeof(hdr_uwdflooding);

                map_all_packets::iterator it2 = my_all_packets_.find(iph->saddr());

                if (it2 != my_all_packets_.end()) {
                    map_packets_state::iterator it3 = it2->second.find(ch->uid());

                	/*
                	 * First time a given packet from and to other nodes
                	 * is encountered, schedule for forwarding after a delay
                	 * drawn uniformly from [Tmin , Tmax ].
                	 */
                    if (it3 == it2->second.end()) {
                        packet_state new_state;
                        new_state.hop = flh->hop();
                        new_state.nd = 0;
                        new_state.is_relayed = false;
                        new_state.timestamp = Scheduler::instance().clock();
                        new_state.timer = new UwdfloodingHandler(this, p->copy());

                        double delay = uniform(t_min_, t_max_);
                        new_state.timer->sched(delay);

                        it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                        printOnLog(Logger::LogLevel::DEBUG,
                            "UWDFLOODING",
                            "recv():: Scheduled broadcast forwarding for UID: " +
                                std::to_string(ch->uid()) + " with delay: " +
                                std::to_string(delay));

                        Packet::free(p);
                        return;
                    }

                	/*
                	 * Additional packets with the same identifier will be
                	 * treated as duplicates.
                	 */
                    // Packet already in map
                    packet_state &st = it3->second;
					/*
                	 * Duplicates received after relaying has been performed
                	 * will be discarded.
					 */
                    if (st.is_relayed) {
                    	/*
                    	 * Duplicates received with a higher hop counter will be
                    	 * counted, nd being the number of duplicates received
                    	 * (not including the original packet or duplicates with
                    	 * the same or a lower hop counter).
                    	 */
                    	if (flh->hop() > st.hop)
                    		st.nd++;

                        printOnLog(Logger::LogLevel::DEBUG,
                            "UWDFLOODING",
                            "recv():: Packet UID: " + std::to_string(ch->uid()) +
                                " already relayed. Dropping duplicate.");
                        Packet::free(p);
                        return;
                    }

                	/*
                	 * Each time a duplicate with a higher hop counter
                	 * is received, the node will draw a random number
                	 * r ∈ (0, 1]. If the number of duplicates received
                	 * nd > NDupl −r, the forwarding is discarded.
                	 * NDupl is a predefined maximum number of duplicates,
                	 * which may be non-integer. This means that if
                	 * nd = floor(NDupl ), the forwarding is discarded with
                	 * probability equal to the fractional part of NDupl .
                	 */
                    if (flh->hop() > st.hop) {
                        st.nd++;
                        double r = uniform(0, 1);
                        if (st.nd > n_dupl_ - r) {
                            if (st.timer != nullptr) {
                                st.timer->force_cancel();
                                Packet::free(st.timer->pkt());
                                delete st.timer;
                                st.timer = nullptr;
                            }
                            printOnLog(Logger::LogLevel::DEBUG,
                                "UWDFLOODING",
                                "recv():: Duplicate threshold reached for UID: " +
                                    std::to_string(ch->uid()) + ". Cancelling timer.");
                            Packet::free(p);
                            return;
                        }
                        Packet::free(p);
                        return;
					}

                	/*
                	 * When a duplicate is received with a lower hop counter
                	 * (having travelled fewer hops) the hop counter of the
                	 * packet to be forwarded will be updated with the new value.
                	 */
                    if (flh->hop() < st.hop) {
                    	st.hop = flh->hop();
                    	printOnLog(Logger::LogLevel::DEBUG,
							"UWDFLOODING",
							"recv():: Hop count updated to " +
								std::to_string(st.hop) + " for UID: " +
								std::to_string(ch->uid()));
                    	Packet::free(p);
                    	return;
                    }

                	// flh.hop == st.hop NOT SET BY RULES -> DROP
                    Packet::free(p);
                    return;
                }

            	/*
				 * First time a given packet from and to other nodes
				 * is encountered, schedule for forwarding after a delay
				 * drawn uniformly from [Tmin , Tmax ].
				 */
                // New source
                packet_state new_state;
                new_state.hop = flh->hop();
                new_state.nd = 0;
                new_state.is_relayed = false;
                new_state.timestamp = Scheduler::instance().clock();
                new_state.timer = new UwdfloodingHandler(this, p->copy());

                double delay = uniform(t_min_, t_max_);
                new_state.timer->sched(delay);

                map_packets_state new_map;
                new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: New source " + printIP(iph->saddr()) +
                        " registered. Scheduled UID: " + std::to_string(ch->uid()));

                Packet::free(p);
                return;
            }

        	// Unicast packet not for this node - forward
            if (iph->daddr() != ipAddr_) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: Processing unicast packet UID: " +
                        std::to_string(ch->uid()) + " from src: " +
                        printIP(iph->saddr()) + "to dst: " +
                        printIP(iph->daddr()));

                // SendDown setup
                ch->direction() = hdr_cmn::DOWN;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;

                map_all_packets::iterator it2 = my_all_packets_.find(iph->saddr());

                if (it2 != my_all_packets_.end()) {
                    map_packets_state::iterator it3 = it2->second.find(ch->uid());

                	/*
                	 * First time a given packet from and to other nodes
                	 * is encountered, schedule for forwarding after a delay
                	 * drawn uniformly from [Tmin , Tmax ].
                	 */
                    if (it3 == it2->second.end()) {
                        packet_state new_state;
                        new_state.hop = flh->hop();
                        new_state.nd = 0;
                        new_state.is_relayed = false;
                        new_state.timestamp = Scheduler::instance().clock();
                        new_state.timer = new UwdfloodingHandler(this, p->copy());

                        double delay = uniform(t_min_, t_max_);
                        new_state.timer->sched(delay);

                        it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                        printOnLog(Logger::LogLevel::DEBUG,
                            "UWDFLOODING",
                            "recv():: Scheduled broadcast forwarding for UID: " +
                                std::to_string(ch->uid()) + " with delay: " +
                                std::to_string(delay));

                        Packet::free(p);
                        return;
                    }

                	/*
                	 * Additional packets with the same identifier will be
                	 * treated as duplicates.
                	 */
                    // Packet already in map
                    packet_state &st = it3->second;
					/*
                	 * Duplicates received after relaying has been performed
                	 * will be discarded.
					 */
                    if (st.is_relayed) {
                    	/*
                    	 * Duplicates received with a higher hop counter will be
                    	 * counted, nd being the number of duplicates received
                    	 * (not including the original packet or duplicates with
                    	 * the same or a lower hop counter).
                    	 */
                    	if (flh->hop() > st.hop)
                    		st.nd++;

                        printOnLog(Logger::LogLevel::DEBUG,
                            "UWDFLOODING",
                            "recv():: Packet UID: " + std::to_string(ch->uid()) +
                                " already relayed. Dropping duplicate.");
                        Packet::free(p);
                        return;
                    }

                	/*
                	 * Each time a duplicate with a higher hop counter
                	 * is received, the node will draw a random number
                	 * r ∈ (0, 1]. If the number of duplicates received
                	 * nd > NDupl −r, the forwarding is discarded.
                	 * NDupl is a predefined maximum number of duplicates,
                	 * which may be non-integer. This means that if
                	 * nd = floor(NDupl ), the forwarding is discarded with
                	 * probability equal to the fractional part of NDupl .
                	 */
                    if (flh->hop() > st.hop) {
                        st.nd++;
                        double r = uniform(0, 1);
                        if (st.nd > n_dupl_ - r) {
                            if (st.timer != nullptr) {
                                st.timer->force_cancel();
                                Packet::free(st.timer->pkt());
                                delete st.timer;
                                st.timer = nullptr;
                            }
                            printOnLog(Logger::LogLevel::DEBUG,
                                "UWDFLOODING",
                                "recv():: Duplicate threshold reached for UID: " +
                                    std::to_string(ch->uid()) + ". Cancelling timer.");
                            Packet::free(p);
                            return;
                        }
                        Packet::free(p);
                        return;
					}

                	/*
                	 * When a duplicate is received with a lower hop counter
                	 * (having travelled fewer hops) the hop counter of the
                	 * packet to be forwarded will be updated with the new value.
                	 */
                    if (flh->hop() < st.hop) {
                    	st.hop = flh->hop();
                    	printOnLog(Logger::LogLevel::DEBUG,
							"UWDFLOODING",
							"recv():: Hop count updated to " +
								std::to_string(st.hop) + " for UID: " +
								std::to_string(ch->uid()));
                    	Packet::free(p);
                    	return;
                    }

                	// flh.hop == st.hop NOT SET BY RULES -> DROP
                    Packet::free(p);
                    return;
                }

            	/*
				 * First time a given packet from and to other nodes
				 * is encountered, schedule for forwarding after a delay
				 * drawn uniformly from [Tmin , Tmax ].
				 */
                // New source
                packet_state new_state;
                new_state.hop = flh->hop();
                new_state.nd = 0;
                new_state.is_relayed = false;
                new_state.timestamp = Scheduler::instance().clock();
                new_state.timer = new UwdfloodingHandler(this, p->copy());

                double delay = uniform(t_min_, t_max_);
                new_state.timer->sched(delay);

                map_packets_state new_map;
                new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: New source " + printIP(iph->saddr()) +
                        " registered. Scheduled UID: " + std::to_string(ch->uid()));

                Packet::free(p);
                return;
            }


            printOnLog(Logger::LogLevel::DEBUG,
                "UWDFLOODING",
                "recv()::UP - Unexpected state reached for UID: " +
                    std::to_string(ch->uid()));
            Packet::free(p);
            return;
        }

        if (ch->direction() == hdr_cmn::DOWN) {

            if (iph->daddr() == 0) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: ERROR - Destination is 0 on DOWN packet.");
                Packet::free(p);
                return;
            }

            if (iph->daddr() == ipAddr_) {
                printOnLog(Logger::LogLevel::DEBUG,
                    "UWDFLOODING",
                    "recv():: DOWN packet reached destination " + std::to_string(ipAddr_));
                sendUp(p);
                return;
            }

        	/*
        	 * When a new packet is received from the application
        	 * layer, send down to MAC layer immediately with hop
        	 * counter set to 1.
        	 */
            // Forward packet down
            ch->prev_hop_ = ipAddr_;
            ch->next_hop() = UWIP_BROADCAST;
            ch->size() += sizeof(hdr_uwdflooding);
            flh->hop() = 1;

            printOnLog(Logger::LogLevel::DEBUG,
                "UWDFLOODING",
                "recv():: Forwarding DOWN packet UID: " + std::to_string(ch->uid()));

            sendDown(p);
            return;
        }

        printOnLog(Logger::LogLevel::DEBUG,
            "UWDFLOODING",
            "recv():: ERROR - Unknown direction for UID: " + std::to_string(ch->uid()));
        Packet::free(p);
        return;
    }

    // Error flag set - drop packet
    printOnLog(Logger::LogLevel::DEBUG,
        "UWDFLOODING",
        "recv():: Packet received with ERROR flag. Dropping UID: " +
            std::to_string(ch->uid()));
    Packet::free(p);
}/* UwDflooding::recv */

string
UwDflooding::printIP(const nsaddr_t &ip_)
{
	stringstream out;
	out << ((ip_ & 0xff000000) >> 24);
	out << ".";
	out << ((ip_ & 0x00ff0000) >> 16);
	out << ".";
	out << ((ip_ & 0x0000ff00) >> 8);
	out << ".";
	out << ((ip_ & 0x000000ff));
	return out.str();
} /* UwDflooding::printIP */