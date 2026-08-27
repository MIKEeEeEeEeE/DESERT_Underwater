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

#include "uwcpflooding-hdr.h"
#include "uwcpflooding.h"

extern packet_t PT_UWCPFLOODING;
extern packet_t PT_UWCPFLOODING_NOTIFICATION;

int hdr_uwcpflooding::offset_ = 0; /**< Offset used to access in
										<i>hdr_uwcpflooding</i> packets header. */

/**
 * Adds the module for UwCPFlooding in ns2.
 */
static class UwCPFloodingModuleClass : public TclClass
{
public:
    UwCPFloodingModuleClass()
        : TclClass("Module/UW/CPFLOODING")
    {
    }

    TclObject*
    create(int, const char *const *)
    {
        return (new UwCPFlooding());
    }
} class_mod_uwcpflooding;

/**
 * Adds the header for <i>hdr_uwcpflooding</i> packets in ns2.
 */
static class UwCPFloodingPktClass : public PacketHeaderClass
{
public:
    UwCPFloodingPktClass()
        : PacketHeaderClass("PacketHeader/CPFLOODING", sizeof(hdr_uwcpflooding))
    {
        this->bind();
        bind_offset(&hdr_uwcpflooding::offset_);
    }
} class_uwcpflooding_pkt;

UwCPFloodingHandler::UwCPFloodingHandler(UwCPFlooding *m, Packet* p)
    : TimerHandler()
    , module_(m)
    , pkt_(p)
{
}

UwCPFloodingHandler::~UwCPFloodingHandler()
{
}

void
UwCPFloodingHandler::expire(Event *e)
{
    module_->doForward(pkt_);
}

Packet*
UwCPFloodingHandler::pkt() const
{
    return pkt_;
}

UwCPFlooding::UwCPFlooding()
    : ipAddr_(0)
    , packets_forwarded_(0)
    , trace_path_(false)
    , trace_file_path_name_((char *) "trace")
    , te_(0.0)
{ // Binding to TCL variables.
    bind("debug_", &debug_);
} /* UwCPFlooding::UwCPFlooding */

UwCPFlooding::~UwCPFlooding()
{
} /* UwCPFlooding::~UwCPFlooding */

int
UwCPFlooding::recvSyncClMsg(ClMessage *m)
{
    return Module::recvSyncClMsg(m);
} /* UwCPFlooding::recvSyncClMsg */

int
UwCPFlooding::recvAsyncClMsg(ClMessage *m)
{
    return Module::recvAsyncClMsg(m);
} /* UwCPFlooding::recvAsyncClMsg */

void
UwCPFlooding::doForward(Packet *p)
{
    hdr_uwcpflooding *fh = HDR_UWCPFLOODING(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_cmn *ch = HDR_CMN(p);

    // ОБНОВЛЕНИЕ COVERAGE PROBABILITY НЕПОСРЕДСТВЕННО ПЕРЕД ОТПРАВКОЙ
    map_all_packets::iterator it = my_all_packets_.find(iph->saddr());
    if (it != my_all_packets_.end()) {
        map_packets_state::iterator it2 = it->second.find(ch->uid());
        if (it2 != it->second.end()) {
            packet_state &st = it2->second;
            auto& local_cp = st.coverage_map;
            te_ = 0.0;
            for (const auto& pair : link_quality_neighbors) {
                uint8_t curr_k = pair.first;
                double Luk = pair.second;
                double cprobK = local_cp[curr_k];
            	cprobK = 1 - (1 - cprobK) * (1 - Luk);
            	local_cp[curr_k] = cprobK;
            	if (cprobK < 0.9)
					te_ += Luk * (1.0 - cprobK);
            }
            fh->hop() = st.hop;
            fh->hop()++;
            fh->prev_prev_hop_ = st.prev_prev_hop_;
            st.is_relayed = true;
            st.timer = nullptr;
        	// st.coverage_map.clear();
        }
    }

    sendDown(p);
    packets_forwarded_++;

    if (trace_path_)
        this->writePathInTrace(p, "FRWD_DTA");
}

int
UwCPFlooding::command(int argc, const char *const *argv)
{
    Tcl &tcl = Tcl::instance();

    if (argc == 2) {
        if (strcasecmp(argv[1], "getpacketsforwarded") == 0) {
            tcl.resultf("%lu", packets_forwarded_);
            return TCL_OK;
        } else if (strcasecmp(argv[1], "getfloodingheadersize") == 0) {
            tcl.resultf("%d", sizeof(hdr_uwcpflooding));
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
    }
    return Module::command(argc, argv);
} /* UwCPFlooding::command */

void
UwCPFlooding::recv(Packet *p)
{
    hdr_cmn *ch = HDR_CMN(p);
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_uwcpflooding *flh = HDR_UWCPFLOODING(p);
	hdr_MPhy *ph = HDR_MPHY(p);


    if (!ch->error()) {
        if (ch->direction() == hdr_cmn::UP) {

        	double snr_linear = (ph && ph->Pn > 0.0) ? (ph->Pr / ph->Pn) : 1.0;
        	double ber = 0.5 * std::erfc(std::sqrt(snr_linear));
        	double num_bits = static_cast<double>(ch->size() * 8);
        	double link_quality =
        		(num_bits > 0.0) ? std::exp(num_bits * std::log1p(-ber)) : 1.0;

        	uint8_t u = ipAddr_;
        	uint8_t v = ch->prev_hop_;
        	uint8_t prev_k = flh->prev_prev_hop_;

        	link_quality_neighbors[v] = link_quality;
        	auto& Bvu = neighbors[std::make_pair(v, u)];
        	auto& Bkv = neighbors[std::make_pair(prev_k, v)];
        	Bvu.insert(ch->uid());
        	Bkv.insert(ch->uid());

            if (trace_path_)
                this->writePathInTrace(p, "RECV_DTA");

            if (iph->daddr() == 0) {
                std::cerr << "Destination address not set." << std::endl;
                if (trace_path_)
                    this->writePathInTrace(p, "FREE_DTA");
                Packet::free(p);
                return;
            }

            // 2. ПАКЕТ ПРЕДНАЗНАЧЕН ЭТОМУ УЗЛУ (НАЗНАЧЕНИЕ)
            if (iph->daddr() == ipAddr_) {
                // Отправляем уведомление
                Packet *notif = Packet::alloc();

                hdr_uwcpflooding *flh_ = HDR_UWCPFLOODING(notif);
                flh_->prev_prev_hop_ = ch->prev_hop_;

                hdr_cmn *ch_ = HDR_CMN(notif);
                ch_->ptype() = PT_UWCPFLOODING_NOTIFICATION;
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

                if (trace_path_)
                    this->writePathInTrace(p, "SDUP_DTA");
                sendUp(p);
                return;
            }

            // Пакет от самого себя (loopback) - сбрасываем
            if (iph->saddr() == ipAddr_) {
                if (trace_path_)
                    this->writePathInTrace(p, "FREE_DTA");
                Packet::free(p);
                return;
            }

            // 3. BROADCAST ПАКЕТ
            if (iph->daddr() == UWIP_BROADCAST) {
                ch->size() -= sizeof(hdr_uwcpflooding);
                if (trace_path_)
                    this->writePathInTrace(p, "SDUP_DTA");
                sendUp(p->copy());

                ch->direction() = hdr_cmn::DOWN;
                flh->prev_prev_hop_ = ch->prev_hop_;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;
                ch->size() += sizeof(hdr_uwcpflooding);


                map_all_packets::iterator it2 =
                    my_all_packets_.find(iph->saddr());

                if (it2 != my_all_packets_.end()) {
                    map_packets_state::iterator it3 =
                        it2->second.find(ch->uid());

                    if (it3 == it2->second.end()) {
                        // Известный источник, новый пакет
                        packet_state new_state;
                        new_state.hop = flh->hop();
                        new_state.is_relayed = false;
                        new_state.timestamp = Scheduler::instance().clock();
                        new_state.timer = new UwCPFloodingHandler(this, p->copy());
                        new_state.prev_prev_hop_ = ch->prev_hop_;
                        // Обновление покрытия и расчёт TE
                        auto& local_cp = new_state.coverage_map;

                        double current_time = Scheduler::instance().clock();

                        te_ = 0.0;
                        for (const auto& pair : link_quality_neighbors) {
                        	uint8_t curr_k = pair.first;
                        	double Luk = pair.second;

                        	if (curr_k == v) {
                        		local_cp[curr_k] = 1.0;
                        		new_state.coverage_timestamps[curr_k] = current_time; // Обновляем время
                        		continue;
                        	}

                        	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                        	auto time_it = new_state.coverage_timestamps.find(curr_k);
                        	if (time_it != new_state.coverage_timestamps.end()) {
                        		// Если запись вышла за пределы временного окна — обнуляем её
                        		if (current_time - time_it->second > time_window) {
                        			local_cp[curr_k] = 0.0;
                        		}
                        	}

                        	double cprobK = local_cp[curr_k];

                        	if (cprobK < 0.9) {
                        		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                        		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                        			std::vector<uint16_t> common;
                        			std::set_intersection(
										Bvu.begin(), Bvu.end(),
										it_bvk->second.begin(), it_bvk->second.end(),
										std::back_inserter(common)
									);
                        			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                        			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                        			local_cp[curr_k] = cprobK;
                        			new_state.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                        		}
                        	}

                        	if (cprobK < 0.9)
                        		te_ += Luk * (1.0 - cprobK);
                        }
                    	std::cout << te_ << std::endl;

                    	// double delay = 50;
                        double delay = 100 / (1.0 + te_);
                        new_state.timer->sched(delay);

                        it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                        if (trace_path_)
                            this->writePathInTrace(p, "SCHD_DTA");
                        Packet::free(p);
                        return;
                    }

                    // Пакет уже есть в карте
                    packet_state &st = it3->second;

                    if (st.is_relayed) {
                        if (trace_path_)
                            this->writePathInTrace(p, "FREE_DTA");
                        Packet::free(p);
                        return;
                    }

                    // Пересчет покрытия при дубликате
                    auto& local_cp = st.coverage_map;

                    double current_time = Scheduler::instance().clock();

                    te_ = 0.0;
                    for (const auto& pair : link_quality_neighbors) {
                    	uint8_t curr_k = pair.first;
                    	double Luk = pair.second;

                    	if (curr_k == v) {
                    		local_cp[curr_k] = 1.0;
                    		st.coverage_timestamps[curr_k] = current_time; // Обновляем время
                    		continue;
                    	}

                    	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                    	auto time_it = st.coverage_timestamps.find(curr_k);
                    	if (time_it != st.coverage_timestamps.end()) {
                    		// Если запись вышла за пределы временного окна — обнуляем её
                    		if (current_time - time_it->second > time_window) {
                    			local_cp[curr_k] = 0.0;
                    		}
                    	}

                    	double cprobK = local_cp[curr_k];

                    	if (cprobK < 0.9) {
                    		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                    		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                    			std::vector<uint16_t> common;
                    			std::set_intersection(
									Bvu.begin(), Bvu.end(),
									it_bvk->second.begin(), it_bvk->second.end(),
									std::back_inserter(common)
								);
                    			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                    			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                    			local_cp[curr_k] = cprobK;
                    			st.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                    		}
                    	}

                    	if (cprobK < 0.9)
                    		te_ += Luk * (1.0 - cprobK);
                    }

                    if (trace_path_)
                        this->writePathInTrace(p, "FREE_DTA");
                    Packet::free(p);
                    return;
                }

                // Новый источник (Broadcast)
                packet_state new_state;
                new_state.hop = flh->hop();
                new_state.is_relayed = false;
                new_state.timestamp = Scheduler::instance().clock();
                new_state.timer = new UwCPFloodingHandler(this, p->copy());
                new_state.prev_prev_hop_ = ch->prev_hop_;
                auto& local_cp = new_state.coverage_map;

                double current_time = Scheduler::instance().clock();

                te_ = 0.0;
                for (const auto& pair : link_quality_neighbors) {
                	uint8_t curr_k = pair.first;
                	double Luk = pair.second;

                	if (curr_k == v) {
                		local_cp[curr_k] = 1.0;
                		new_state.coverage_timestamps[curr_k] = current_time; // Обновляем время
                		continue;
                	}

                	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                	auto time_it = new_state.coverage_timestamps.find(curr_k);
                	if (time_it != new_state.coverage_timestamps.end()) {
                		// Если запись вышла за пределы временного окна — обнуляем её
                		if (current_time - time_it->second > time_window) {
                			local_cp[curr_k] = 0.0;
                		}
                	}

                	double cprobK = local_cp[curr_k];

                	if (cprobK < 0.9) {
                		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                			std::vector<uint16_t> common;
                			std::set_intersection(
								Bvu.begin(), Bvu.end(),
								it_bvk->second.begin(), it_bvk->second.end(),
								std::back_inserter(common)
							);
                			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                			local_cp[curr_k] = cprobK;
                			new_state.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                		}
                	}

                	if (cprobK < 0.9)
                		te_ += Luk * (1.0 - cprobK);
                }
            	std::cout << "488: " << te_ << std::endl;

            	// double delay = 50;
                double delay = 100 / (1.0 + te_);
                new_state.timer->sched(delay);

                map_packets_state new_map;
                new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                if (trace_path_)
                    this->writePathInTrace(p, "SCHD_DTA");
                Packet::free(p);
                return;
            }

            // 4. UNICAST ПАКЕТ НЕ ДЛЯ ЭТОГО УЗЛА (ТРАНЗИТ)
            if (iph->daddr() != ipAddr_) {
                ch->direction() = hdr_cmn::DOWN;
                flh->prev_prev_hop_ = ch->prev_hop_;
                ch->prev_hop_ = ipAddr_;
                ch->next_hop() = UWIP_BROADCAST;


                map_all_packets::iterator it2 =
                    my_all_packets_.find(iph->saddr());
                if (it2 != my_all_packets_.end()) {
                    map_packets_state::iterator it3 =
                        it2->second.find(ch->uid());

                    if (it3 == it2->second.end()) {
                        // Известный источник, новый Unicast пакет
                        packet_state new_state;
                        new_state.hop = flh->hop();
                        new_state.is_relayed = false;
                        new_state.timestamp = Scheduler::instance().clock();
                        new_state.timer = new UwCPFloodingHandler(this, p->copy());
                        new_state.prev_prev_hop_ = ch->prev_hop_;
                        auto& local_cp = new_state.coverage_map;

                        double current_time = Scheduler::instance().clock();

                        te_ = 0.0;
                        for (const auto& pair : link_quality_neighbors) {
                        	uint8_t curr_k = pair.first;
                        	double Luk = pair.second;

                        	if (curr_k == v) {
                        		local_cp[curr_k] = 1.0;
                        		new_state.coverage_timestamps[curr_k] = current_time; // Обновляем время
                        		continue;
                        	}

                        	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                        	auto time_it = new_state.coverage_timestamps.find(curr_k);
                        	if (time_it != new_state.coverage_timestamps.end()) {
                        		// Если запись вышла за пределы временного окна — обнуляем её
                        		if (current_time - time_it->second > time_window) {
                        			local_cp[curr_k] = 0.0;
                        		}
                        	}

                        	double cprobK = local_cp[curr_k];

                        	if (cprobK < 0.9) {
                        		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                        		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                        			std::vector<uint16_t> common;
                        			std::set_intersection(
										Bvu.begin(), Bvu.end(),
										it_bvk->second.begin(), it_bvk->second.end(),
										std::back_inserter(common)
									);
                        			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                        			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                        			local_cp[curr_k] = cprobK;
                        			new_state.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                        		}
                        	}

                        	if (cprobK < 0.9)
                        		te_ += Luk * (1.0 - cprobK);
                        }
                    	std::cout << "571: " << te_ << std::endl;

                    	// double delay = 50;             // 39.02...
                        double delay = 100 / (1.0 + te_); // 38.037180106228874
                        new_state.timer->sched(delay);

                        it2->second.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));

                        if (trace_path_)
                            this->writePathInTrace(p, "SCHD_DTA");
                        Packet::free(p);
                        return;
                    }

                    // Уверенно известный Unicast пакет
                    packet_state &st = it3->second;
                	if (st.is_relayed) {              // ← ЕСТЬ в broadcast
                		Packet::free(p);
                		return;
                	}

                    auto& local_cp = st.coverage_map;

                    double current_time = Scheduler::instance().clock();

                    te_ = 0.0;
                    for (const auto& pair : link_quality_neighbors) {
                    	uint8_t curr_k = pair.first;
                    	double Luk = pair.second;

                    	if (curr_k == v) {
                    		local_cp[curr_k] = 1.0;
                    		st.coverage_timestamps[curr_k] = current_time; // Обновляем время
                    		continue;
                    	}

                    	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                    	auto time_it = st.coverage_timestamps.find(curr_k);
                    	if (time_it != st.coverage_timestamps.end()) {
                    		// Если запись вышла за пределы временного окна — обнуляем её
                    		if (current_time - time_it->second > time_window) {
                    			local_cp[curr_k] = 0.0;
                    		}
                    	}

                    	double cprobK = local_cp[curr_k];

                    	if (cprobK < 0.9) {
                    		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                    		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                    			std::vector<uint16_t> common;
                    			std::set_intersection(
									Bvu.begin(), Bvu.end(),
									it_bvk->second.begin(), it_bvk->second.end(),
									std::back_inserter(common)
								);
                    			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                    			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                    			local_cp[curr_k] = cprobK;
                    			st.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                    		}
                    	}

                    	if (cprobK < 0.9)
                    		te_ += Luk * (1.0 - cprobK);
                    }

                    if (trace_path_)
                        this->writePathInTrace(p, "FREE_DTA");
                    Packet::free(p);
                    return;
                }

                // Новый источник (Unicast)
                packet_state new_state;
                new_state.hop = flh->hop();
                new_state.is_relayed = false;
                new_state.timestamp = Scheduler::instance().clock();
                new_state.timer = new UwCPFloodingHandler(this, p->copy());
                new_state.prev_prev_hop_ = ch->prev_hop_;
                auto& local_cp = new_state.coverage_map;

                double current_time = Scheduler::instance().clock();

                te_ = 0.0;
                for (const auto& pair : link_quality_neighbors) {
                	uint8_t curr_k = pair.first;
                	double Luk = pair.second;

                	if (curr_k == v) {
                		local_cp[curr_k] = 1.0;
                		new_state.coverage_timestamps[curr_k] = current_time; // Обновляем время
                		continue;
                	}

                	// --- ПРОВЕРКА ВРЕМЕННОГО ОКНА ---
                	auto time_it = new_state.coverage_timestamps.find(curr_k);
                	if (time_it != new_state.coverage_timestamps.end()) {
                		// Если запись вышла за пределы временного окна — обнуляем её
                		if (current_time - time_it->second > time_window) {
                			local_cp[curr_k] = 0.0;
                		}
                	}

                	double cprobK = local_cp[curr_k];

                	if (cprobK < 0.9) {
                		auto it_bvk = neighbors.find(std::make_pair(v, curr_k));
                		if (it_bvk != neighbors.end() && !it_bvk->second.empty() && !Bvu.empty()) {
                			std::vector<uint16_t> common;
                			std::set_intersection(
								Bvu.begin(), Bvu.end(),
								it_bvk->second.begin(), it_bvk->second.end(),
								std::back_inserter(common)
							);
                			double Pvku = static_cast<double>(common.size()) / static_cast<double>(Bvu.size());

                			cprobK = 1.0 - (1.0 - cprobK) * (1.0 - Pvku);
                			local_cp[curr_k] = cprobK;
                			new_state.coverage_timestamps[curr_k] = current_time; // Фиксируем время обновления
                		}
                	}

                	if (cprobK < 0.9)
                		te_ += Luk * (1.0 - cprobK);
                }
            	std::cout << "693: " << te_ << std::endl;

                double delay = 100 / (1.0 + te_);
            	// double delay = 50;
                new_state.timer->sched(delay);

                map_packets_state new_map;
                new_map.insert(std::pair<uint16_t, packet_state>(ch->uid(), new_state));
                my_all_packets_.insert(std::pair<uint8_t, map_packets_state>(iph->saddr(), new_map));

                if (trace_path_)
                    this->writePathInTrace(p, "SCHD_DTA");
                Packet::free(p);
                return;
            }

            std::cerr << "State machine ERROR." << std::endl;
            if (trace_path_)
                this->writePathInTrace(p, "FREE_DTA");
            Packet::free(p);
            return;
        }

        // 5. НАПРАВЛЕНИЕ ВНИЗ (ОТПРАВКА С ВЕРХНЕГО УРОВНЯ / DOWN)
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

            // iph->daddr() != ipAddr_ - генерация пакета на отправку
            flh->prev_prev_hop_ = ch->prev_hop_;
            ch->prev_hop_ = ipAddr_;
            ch->next_hop() = UWIP_BROADCAST;
            ch->size() += sizeof(hdr_uwcpflooding);
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

    if (trace_path_)
        this->writePathInTrace(p, "FREE_DTA");
    Packet::free(p);
} /* UwCPFlooding::recv */

void
UwCPFlooding::writePathInTrace(const Packet *p, const string &_info)
{
    hdr_uwip *iph = HDR_UWIP(p);
    hdr_cmn *ch = HDR_CMN(p);

    trace_file_path_.open(trace_file_path_name_, fstream::app);
    osstream_.clear();
    osstream_.str("");
    osstream_ << _info;
    osstream_ << '\t';
    osstream_ << Scheduler::instance().clock();
    osstream_ << '\t';
    osstream_ << static_cast<uint32_t>(ch->uid() & 0x0000ffff);
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
UwCPFlooding::printIP(const nsaddr_t &ip_)
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
} /* UwCPFlooding::printIP */