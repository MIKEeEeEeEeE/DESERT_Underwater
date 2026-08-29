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

#include "uwcpflooding-hdr.h"

#include <tclcl.h>
#include <uwphy-clmsg.h>

extern EmbeddedTcl MUwCPFloodingInitTclCode;

ClMessage_t CLMSG_UWPHY_NEW;

packet_t PT_UWCPFLOODING;
extern "C" int
Uwcpflooding_Init()
{
	PT_UWCPFLOODING = p_info::addPacket("CPFLOODING");
	CLMSG_UWPHY_NEW = ClMessage::addClMessage();
	MUwCPFloodingInitTclCode.load();
	return 0;
}

extern "C" int
Cyguwcpflooding_Init()
{
	Uwcpflooding_Init();
	return 0;
}


packet_t PT_UWCPFLOODING_NOTIFICATION;
extern "C" int
Uwcpflooding_Notification_Init()
{
	PT_UWCPFLOODING_NOTIFICATION = p_info::addPacket("CPFLOODING_NOTIFICATION");
	MUwCPFloodingInitTclCode.load();
	return 0;
}

extern "C" int
Uwcpflooding_Notification()
{
	Uwcpflooding_Notification_Init();
	return 0;
}