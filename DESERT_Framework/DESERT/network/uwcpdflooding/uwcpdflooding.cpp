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


#include <set>
#include <algorithm>
#include <vector>

#include "uwcpdflooding.h"
#include "uwcpdflooding-hdr.h"
#include "uwphysical.h"
#include "uwstats-utilities.h"


#define uniform(a, b)  ((RNG::defaultrng()->uniform_double() * ((b) - (a)) + (a)))

extern packet_t PT_UWCPDFLOODING;
extern packet_t PT_UWCPDFLOODING_NOTIFICATION;

int hdr_uwcpdflooding::offset_ = 0; /**< Offset used to access in
                                     <i>hdr_uwdflooding</i> packets header. */

/**
 * Adds the module for UwDflooding in ns2.
 */
static class UwCPDfloodingModuleClass : public TclClass
{
public:
    UwCPDfloodingModuleClass()
        : TclClass("Module/UW/CPDFLOODING")
    {
    }

    TclObject*
    create(int, const char *const *)
    {
        return (new UwCPDflooding());
    }
} class_mod_uwcpdflooding;

/**
 * Adds the header for <i>hdr_uwdflooding</i> packets in ns2.
 */
static class UwCPDfloodingPktClass : public PacketHeaderClass
{
public:
    UwCPDfloodingPktClass()
        : PacketHeaderClass("PacketHeader/CPDFLOODING", sizeof(hdr_uwcpdflooding))
    {
        this->bind();
        bind_offset(&hdr_uwcpdflooding::offset_);
    }
} class_uwcpdflooding_pkt;

UwcpdfloodingHandler::UwcpdfloodingHandler(UwCPDflooding *m, Packet* p)
    : TimerHandler()
    , module_(m)
    , pkt_(p)
{
}

UwcpdfloodingHandler::~UwcpdfloodingHandler()
{
}

void
UwcpdfloodingHandler::expire(Event *e)
{
    module_->doForward(pkt_);
}

Packet*
UwcpdfloodingHandler::pkt() const
{
	return pkt_;
}

UwCPDflooding::UwCPDflooding()
    : ipAddr_(0)
	, debug_(0)
    , ttl_(10)
    , optimize_(1)
    , packets_forwarded_(0)
	, trace_path_(false)
	, trace_file_path_name_((char *) "trace")
	, te_(0.0)
	, t_min_(0.0)
	, t_max_(0.0)
    , n_dupl_(0)
	, t_dupl_(0)
    , ttl_traffic_map()
	, stats_phy_id(0)
{ // Binding to TCL variables.
    bind("ttl_", &ttl_);
	bind("t_delay_", &t_delay_);
    bind("n_dupl_", &n_dupl_);
    bind("t_dupl_", &t_dupl_);
    bind("optimize_", &optimize_);
	bind("debug_", &debug_);
	bind("t_min_", &t_min_);
	bind("t_max_", &t_max_);
} /* UwDflooding::UwDflooding */

UwCPDflooding::~UwCPDflooding()
{
} /* UwDflooding::~UwDflooding */

int
UwCPDflooding::recvSyncClMsg(ClMessage *m)
{
    return Module::recvSyncClMsg(m);
} /* UwDflooding::recvSyncClMsg */

int
UwCPDflooding::recvAsyncClMsg(ClMessage *m)
{
    return Module::recvAsyncClMsg(m);
} /* UwDflooding::recvAsyncClMsg */

void
UwCPDflooding::doForward(Packet *p)
{
    hdr_uwcpdflooding *fh = HDR_UWCPDFLOODING(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_cmn *ch = HDR_CMN(p);

    map_all_packets::iterator it = my_all_packets_.find(iph->saddr());
    if (it != my_all_packets_.end()) {
        map_packets_state::iterator it2 = it->second.find(ch->uid());
        if (it2 != it->second.end()) {
            packet_state &st = it2->second;
            fh->hop() = st.hop;
            fh->hop()++;
        	fh->prev_prev_hop_ = st.prev_prev_hop_;
            st.is_relayed = true;
            st.timer = nullptr;
        }
    }

    sendDown(p);
    packets_forwarded_++;

    if (trace_path_)
    	this->writePathInTrace(p, "FRWD_DTA");
}

int
UwCPDflooding::command(int argc, const char *const *argv)
{
	Tcl &tcl = Tcl::instance();

	if (argc == 2) {
		if (strcasecmp(argv[1], "getpacketsforwarded") == 0) {
			tcl.resultf("%lu", packets_forwarded_);
			return TCL_OK;
		} else if (strcasecmp(argv[1], "getfloodingheadersize") == 0) {
			tcl.resultf("%d", sizeof(hdr_uwcpdflooding));
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
		} else if (strcasecmp(argv[1], "trace") == 0) {
			string tmp_ = ((char *) argv[2]);
			trace_file_path_name_ = new char[tmp_.length() + 1];
			strcpy(trace_file_path_name_, tmp_.c_str());
			if (trace_file_path_name_ == NULL) {
				fprintf(stderr, "Empty string for the trace file name");
				return TCL_ERROR;
			}
			trace_path_ = true;
			remove(trace_file_path_name_);
			trace_file_path_.open(trace_file_path_name_);
			trace_file_path_.close();
			return TCL_OK;
		}
	} else if (argc == 4) {
		if (strcasecmp(argv[1], "addTtlPerTraffic") == 0) {
			ttl_traffic_map[static_cast<uint16_t>(atoi(argv[2]))] =
					static_cast<uint8_t>(atoi(argv[3]));
			return TCL_OK;
		}
	}
	return Module::command(argc, argv);
} /* UwDflooding::command */

void
UwCPDflooding::recv(Packet *p)
{
    hdr_cmn *ch = HDR_CMN(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_uwcpdflooding *flh = HDR_UWCPDFLOODING(p);

    if (!ch->error()) {
        if (ch->direction() == hdr_cmn::UP) {

        	uint8_t u = ipAddr_;
        	uint8_t v = ch->prev_hop_;
        	uint8_t k = flh->prev_prev_hop_;
        	auto& Bvu = neighbors[make_pair(v, u)];
        	auto& Bvk = neighbors[make_pair(v, k)];
        	Bvu.insert(ch->uid());
        	Bvk.insert(ch->uid());
        	std::vector<uint16_t> common;
        	std::set_intersection(
				Bvu.begin(), Bvu.end(),
				Bvk.begin(), Bvk.end(),
				std::back_inserter(common)
			);
        	const double Pvku = static_cast<double>(common.size()) / Bvu.size();
        	auto& probability = coverage_prob[k];
        	te_ -= probability;
        	probability = 1.0 - (1.0 - probability) * (1.0 - Pvku);
			te_ += probability;
        	std::cout << probability << std::endl;
        	std::cout << Pvku << std::endl;




        	// Cancel by timer (Acknowledgement received)
        	if (ch->ptype() == PT_UWCPDFLOODING_NOTIFICATION) {
        		if (trace_path_)
        			this->writePathInTrace(p, "RECV_ACK");

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
        				if (trace_path_)
        					this->writePathInTrace(p, "CNCL_FRWD");
        			}
        		}
        		Packet::free(p);
        		return;
        	}
        	if (trace_path_)
        		this->writePathInTrace(p, "RECV_DTA");

            if (iph->daddr() == 0) {
                std::cerr << "Destination address not set." << std::endl;
                if (trace_path_)
                    this->writePathInTrace(p, "FREE_DTA");
                Packet::free(p);
                return;
            }

            // Packet destined to this node
            if (iph->daddr() == ipAddr_) {
            	// Senf notification message
                Packet *notif = Packet::alloc();

            	hdr_uwcpdflooding *flh_ = HDR_UWCPDFLOODING(notif);
            	flh_->prev_prev_hop_ = ch->prev_hop_;

            	hdr_cmn *ch_ = HDR_CMN(notif);
            	ch_->ptype() = PT_UWCPDFLOODING_NOTIFICATION;
                ch_->size() = 0;
            	ch_->uid() = ch->uid();
                ch_->direction() = hdr_cmn::DOWN;
                ch_->prev_hop_ = ipAddr_;
                ch_->next_hop() = UWIP_BROADCAST;

            	hdr_uwip *iph_ = HDR_UWIP(notif);
            	iph_->saddr() = iph->saddr();
            	iph_->daddr() = UWIP_BROADCAST;

                if (trace_path_)
                    this->writePathInTrace(notif, "FRWD_NTFC");

                sendDown(notif);

            	flh->ttl()--;
                if (trace_path_)
                    this->writePathInTrace(p, "SDUP_DTA");
                sendUp(p);
                return;
            }

            // Packet from this node (loopback) - discard
            if (iph->saddr() == ipAddr_) {
                if (trace_path_)
                    this->writePathInTrace(p, "FREE_DTA");
                Packet::free(p);
                return;
            }

            // Broadcast packet
            if (iph->daddr() == UWIP_BROADCAST) {
                // sendUp always: the destination is in broadcast.
                ch->size() -= sizeof(hdr_uwcpdflooding);
                if (trace_path_)
                    this->writePathInTrace(p, "SDUP_DTA");
                sendUp(p->copy());

                // SendDown
                ch->direction() = hdr_cmn::DOWN;
            	flh->prev_prev_hop_ = ch->prev_hop_;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;
                flh->ttl()--;
                ch->size() += sizeof(hdr_uwcpdflooding);

                if (flh->ttl() <= 0) {
                    if (trace_path_)
                        this->writePathInTrace(p, "DROP_TTL");
                    drop(p, 1, TTL_EQUALS_TO_ZERO);
                    return;
                }

                if (optimize_) {
                    map_all_packets::iterator it2 =
                    	my_all_packets_.find(iph->saddr());

                    if (it2 != my_all_packets_.end()) {
                        map_packets_state::iterator it3 =
                        	it2->second.find(ch->uid());

                        if (it3 == it2->second.end()) {
                            // Known source but new packet -> add to map and schedule forwarding
                            packet_state new_state;
                            new_state.hop = flh->hop();
                            new_state.nd = 0;
                            new_state.is_relayed = false;
                        	new_state.timestamp = Scheduler::instance().clock();
                            new_state.timer = new UwcpdfloodingHandler(this, p->copy());
                        	new_state.prev_prev_hop_ = ch->prev_hop_;

                        	double delay = uniform(t_min_, t_max_) * (1.0 + te_);
                            new_state.timer->sched(delay);

                            it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                            if (trace_path_)
                            	this->writePathInTrace(p, "SCHD_DTA");
                        	Packet::free(p);
                            return;
                        }

                        // Packet already in map
                        packet_state &st = it3->second;

                        if (st.is_relayed) {
                            if (trace_path_)
                                this->writePathInTrace(p, "FREE_DTA");
                            Packet::free(p);
                            return;
                        }

                        if (flh->hop() > st.hop) {
	                        if (Scheduler::instance().clock() -
								st.timestamp <= t_dupl_) {
	                        	st.nd++;
	                        	double r = uniform(0, 1);
	                        	if (st.nd > n_dupl_ - r) {
	                        		if (st.timer != nullptr) {
	                        			st.timer->force_cancel();
	                        			Packet::free(st.timer->pkt());
	                        			delete st.timer;
	                        			st.timer = nullptr;
	                        		}
	                        		if (trace_path_)
	                        			this->writePathInTrace(p, "CNCL_DUP");
	                        		Packet::free(p);
	                        		return;
	                        	}
	                        	if (trace_path_)
	                        		this->writePathInTrace(p, "FREE_DTA");
	                        	Packet::free(p);
	                        	return;
								} else {
									// T_Dupl window expired,
									// just drop duplicate but keep timer
									if (trace_path_)
										this->writePathInTrace(p, "FREE_DTA");
									Packet::free(p);
									return;
								}
                        }


                        if (flh->hop() < st.hop) {
							st.hop = flh->hop();
                            if (trace_path_)
                                this->writePathInTrace(p, "UPDT_HOP");
                            Packet::free(p);
                            return;
                        }

                        // Same hop count
                        // Not set by rules
                        if (trace_path_)
                            this->writePathInTrace(p, "FREE_DTA");
                        Packet::free(p);
                        return;
                    }

                    // New source - add to map and schedule forwarding
                    packet_state new_state;
                    new_state.hop = flh->hop();
                    new_state.nd = 0;
                    new_state.is_relayed = false;
                    new_state.timestamp = Scheduler::instance().clock();
                    new_state.timer = new UwcpdfloodingHandler(this, p->copy());
                	new_state.prev_prev_hop_ = ch->prev_hop_;

                	double delay = uniform(t_min_, t_max_) * (1.0 + te_);
                    new_state.timer->sched(delay);

                    map_packets_state new_map;
                    new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                    my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                    if (trace_path_)
                        this->writePathInTrace(p, "SCHD_DTA");
                    Packet::free(p);
                    return;
                }

                // No optimization - forward immediately
                packets_forwarded_++;
                if (trace_path_)
                    this->writePathInTrace(p, "FRWD_DTA");
                sendDown(p);
                return;
            }

            // Unicast packet not for this node - forward
            if (iph->daddr() != ipAddr_) {
                ch->direction() = hdr_cmn::DOWN;
            	flh->prev_prev_hop_ = ch->prev_hop_;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;
                flh->ttl()--;

                if (flh->ttl() <= 0) {
                    if (trace_path_)
                        this->writePathInTrace(p, "DROP_TTL");
                    drop(p, 1, TTL_EQUALS_TO_ZERO);
                    return;
                }

                if (optimize_) {
                    map_all_packets::iterator it2 =
                    	my_all_packets_.find(iph->saddr());
                    if (it2 != my_all_packets_.end()) {
                        map_packets_state::iterator it3 =
                        	it2->second.find(ch->uid());

                        if (it3 == it2->second.end()) {
                            // Known source and new packet -> add it and forward
                        	packet_state new_state;
                        	new_state.hop = flh->hop();
                        	new_state.nd = 0;
                        	new_state.is_relayed = false;
                        	new_state.timestamp = Scheduler::instance().clock();
                        	new_state.timer = new UwcpdfloodingHandler(this, p->copy());
                        	new_state.prev_prev_hop_ = ch->prev_hop_;

                        	double delay = uniform(t_min_, t_max_) * (1.0 + te_);
                        	new_state.timer->sched(delay);

                        	it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                        	if (trace_path_)
                        		this->writePathInTrace(p, "SCHD_DTA");
                        	Packet::free(p);
                        	return;
                        }
                        // Packet already seen - drop
                    	packet_state &st = it3->second;
                    	if (flh->hop() > st.hop) {
                    		if (Scheduler::instance().clock() -
								st.timestamp <= t_dupl_) {
                    			st.nd++;
                    			double r = uniform(0, 1);
                    			if (st.nd > n_dupl_ - r) {
                    				if (st.timer != nullptr) {
                    					st.timer->force_cancel();
                    					Packet::free(st.timer->pkt());
                    					delete st.timer;
                    					st.timer = nullptr;
                    				}
                    				if (trace_path_)
                    					this->writePathInTrace(p, "CNCL_DUP");
                    				Packet::free(p);
                    				return;
                    			}
                    			if (trace_path_)
                    				this->writePathInTrace(p, "FREE_DTA");
                    			Packet::free(p);
                    			return;
								}
							// T_Dupl window expired,
							// just drop duplicate but keep timer
							if (trace_path_)
								this->writePathInTrace(p, "FREE_DTA");
							Packet::free(p);
							return;
						}

                    	if (flh->hop() < st.hop) {
                    		st.hop = flh->hop();
                    		if (trace_path_)
                    			this->writePathInTrace(p, "UPDT_HOP");
                    		Packet::free(p);
                    		return;
                    	}

                    	// Same hop count
                    	// Not set by rules
                    	if (trace_path_)
                    		this->writePathInTrace(p, "FREE_DTA");
                    	Packet::free(p);
                    	return;
                    }

                    // New source - forward
                	packet_state new_state;
                	new_state.hop = flh->hop();
                	new_state.nd = 0;
                	new_state.is_relayed = false;
                	new_state.timestamp = Scheduler::instance().clock();
                	new_state.timer = new UwcpdfloodingHandler(this, p->copy());
                	new_state.prev_prev_hop_ = ch->prev_hop_;

                	double delay = uniform(t_min_, t_max_) * (1.0 + te_);
                	new_state.timer->sched(delay);

                	map_packets_state new_map;
                	new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                	my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                	if (trace_path_)
                		this->writePathInTrace(p, "SCHD_DTA");
                	Packet::free(p);
                	return;
                }

                if (trace_path_)
                    this->writePathInTrace(p, "FRWD_DTA");
                packets_forwarded_++;
            	sendDown(p);
                return;
            }

            std::cerr << "State machine ERROR." << std::endl;
            if (trace_path_)
                this->writePathInTrace(p, "FREE_DTA");
            Packet::free(p);
            return;
        }

        if (ch->direction() == hdr_cmn::DOWN) {
            if (trace_path_)
                this->writePathInTrace(p, "RECV_DTA");

            if (iph->daddr() == 0) {
                std::cerr << "Destination address equals to 0." << std::endl;
                if (trace_path_)
                    this->writePathInTrace(p, "FREE_DTA");
                Packet::free(p);
                return;
            }

            if (iph->daddr() == ipAddr_) {
                if (trace_path_)
                    this->writePathInTrace(p, "SDUP_DTA");
                sendUp(p);
                return;
            }

            // iph->daddr() != ipAddr_ - forward the packet
        	flh->prev_prev_hop_ = ch->prev_hop_;
        	ch->prev_hop_ = ipAddr_;
            ch->next_hop() = UWIP_BROADCAST;
            ch->size() += sizeof(hdr_uwcpdflooding);
            flh->ttl() = getTTL(p);
            flh->hop() = 1;

            if (trace_path_)
                this->writePathInTrace(p, "FRWD_DTA");
            sendDown(p);
            return;
        }

        std::cerr << "Direction different from UP or DOWN." << std::endl;
        if (trace_path_)
            this->writePathInTrace(p, "FREE_DTA");
        Packet::free(p);
        return;
    }

    // Error flag set - drop packet
    if (trace_path_)
        this->writePathInTrace(p, "FREE_DTA");
    Packet::free(p);
} /* UwDflooding::recv */

uint8_t
UwCPDflooding::getTTL(Packet *p) const
{
	hdr_uwcbr *uwcbrh = HDR_UWCBR(p);
	auto it = ttl_traffic_map.find(uwcbrh->traffic_type());
	if (it != ttl_traffic_map.end()) {
		return it->second;
	}
	return ttl_;
}

void
UwCPDflooding::writePathInTrace(const Packet *p, const string &_info)
{
	hdr_uwip *iph = HDR_UWIP(p);
	hdr_cmn *ch = HDR_CMN(p);
	hdr_uwcpdflooding *flh = HDR_UWCPDFLOODING(p);

	trace_file_path_.open(trace_file_path_name_, fstream::app);
	osstream_.clear();
	osstream_.str("");
	osstream_ << _info;
	osstream_ << '\t';
	osstream_ << Scheduler::instance().clock();
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(ch->uid() & 0x0000ffff);
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(flh->ttl());
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(ch->prev_hop_ & 0x000000ff);
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(ch->next_hop() & 0x000000ff);
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(iph->saddr());
	osstream_ << '\t';
	osstream_ << static_cast<uint32_t>(iph->daddr());
	osstream_ << '\t';
	osstream_ << ch->direction();
	osstream_ << '\t';
	osstream_ << ch->ptype();
	trace_file_path_ << osstream_.str() << endl;
	trace_file_path_.close();
}

string
UwCPDflooding::printIP(const nsaddr_t &ip_)
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