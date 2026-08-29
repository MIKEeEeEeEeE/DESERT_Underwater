# Copyright (c) 2015 Regents of the SIGNET lab, University of Padova.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University of Padova (SIGNET lab) nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# Author: Giovanni Toso <tosogiov@dei.unipd.it>
# Version: 1.0.0

######################################
# Flags to enable or disable options #
######################################
set opt(verbose)            1
set opt(bash_parameters)    0
set opt(trace_files)        0

#####################
# Library Loading   #
#####################
load libMiracle.so
load libMiracleBasicMovement.so
load libmphy.so
load libUwmStd.so
load libuwinterference.so
load libuwphy_clmsgs.so
load libuwstats_utilities.so
load libuwphysical.so
load libuwcsmaaloha.so
load libuwip.so
load libuwmll.so
load libuwudp.so
load libuwcbr.so
load libuwcpflooding.so

#############################
# NS-Miracle initialization #
#############################
set ns [new Simulator]
$ns use-Miracle

##################
# Tcl variables  #
##################
set opt(start_clock) [clock seconds]

# --- Parameters imported from DESERT TDMA configuration ---
set opt(nn)                 8 ;# Total Number of Mesh Nodes
set opt(starttime)          1
set opt(stoptime)           1000
set opt(txduration)         [expr {$opt(stoptime) - $opt(starttime)}]
set opt(seedcbr)            1

set opt(maxinterval_)       50.0
set opt(freq)               25000.0
set opt(bw)                 5000.0
set opt(bitrate)            2400.0   ;# TDMA Standard Bitrate

set opt(txpower)            180.0    ;# TDMA Standard Transmit Power (dB re uPa)
set opt(per_tgt)            0.01
set opt(rx_snr_penalty_db)  0.0
set opt(tx_margin_db)       10.0

set rng [new RNG]
$rng seed $opt(seedcbr)

set opt(pktsize)    64      ;# TDMA standard packet size (bytes)
set opt(cbr_period) 20      ;# TDMA standard CBR interval (s)

# --- Dynamic Flooding-specific protocol tuning ---
set opt(ttl)        6
set opt(cache_time) 600

if {$opt(trace_files)} {
    set opt(tracefilename) "./test_uwcpflooding.tr"
    set opt(tracefile) [open $opt(tracefilename) w]
    set opt(cltracefilename) "./test_uwcpflooding.cltr"
    set opt(cltracefile) [open $opt(cltracefilename) w]
} else {
    set opt(tracefilename) "/dev/null"
    set opt(tracefile) [open $opt(tracefilename) w]
    set opt(cltracefilename) "/dev/null"
    set opt(cltracefile) [open $opt(cltracefilename) w]
}

set channel [new Module/UnderwaterChannel]
set propagation [new MPropagation/Underwater]
set data_mask [new MSpectralMask/Rect]
$data_mask setFreq       $opt(freq)
$data_mask setBandwidth  $opt(bw)

#########################
# Module Configuration  #
#########################
Module/UW/CBR set packetSize_          $opt(pktsize)
Module/UW/CBR set period_              $opt(cbr_period)
Module/UW/CBR set PoissonTraffic_      0
Module/UW/CBR set drop_out_of_order_   0

# Dynamic Flooding (UW/CPFLOODING) Parameters

Module/UW/CSMA_ALOHA set buffer_pkts_    100
Module/UW/CSMA_ALOHA set max_tx_tries_   3

Module/UW/PHYSICAL set debug_                    0
Module/UW/PHYSICAL set BitRate_                  $opt(bitrate)
Module/UW/PHYSICAL set AcquisitionThreshold_dB_  10.0
Module/UW/PHYSICAL set RxSnrPenalty_dB_          $opt(rx_snr_penalty_db)
Module/UW/PHYSICAL set TxSPLMargin_dB_            $opt(tx_margin_db)
Module/UW/PHYSICAL set MaxTxSPL_dB_              $opt(txpower)
Module/UW/PHYSICAL set MinTxSPL_dB_              10
Module/UW/PHYSICAL set MaxTxRange_                40000
Module/UW/PHYSICAL set PER_target_                $opt(per_tgt)
Module/UW/PHYSICAL set CentralFreqOptimization_  0
Module/UW/PHYSICAL set BandwidthOptimization_    0
Module/UW/PHYSICAL set SPLOptimization_          1

################################
# Procedure to create Mesh Node#
################################
proc createNode { id } {
    global channel propagation data_mask ns cbr position node udp portnum ipr ipif
    global phy posdb opt mll mac interf_data

    set node($id) [$ns create-M_Node $opt(tracefile) $opt(cltracefile)]

    # Dynamic allocation: Create CBR instances for (nn - 1) peers
    for {set target 0} {$target < $opt(nn)} {incr target} {
        if {$id != $target} {
            set cbr($id,$target) [new Module/UW/CBR]
        }
    }

    set udp($id)  [new Module/UW/UDP]
    set ipr($id)  [new Module/UW/CPFLOODING]
    set ipif($id) [new Module/UW/IP]
    set mll($id)  [new Module/UW/MLL]
    set mac($id)  [new Module/UW/CSMA_ALOHA]
    set phy($id)  [new Module/UW/PHYSICAL]

    # Attach layer 7 applications
    for {set target 0} {$target < $opt(nn)} {incr target} {
        if {$id != $target} {
            $node($id) addModule 7 $cbr($id,$target) 0 "CBR"
        }
    }

    $node($id) addModule 6 $udp($id)   0 "UDP"
    $node($id) addModule 5 $ipr($id)   0 "IPR"
    $node($id) addModule 4 $ipif($id)  0 "IPF"
    $node($id) addModule 3 $mll($id)   0 "MLL"
    $node($id) addModule 2 $mac($id)   0 "MAC"
    $node($id) addModule 1 $phy($id)   0 "PHY"

    # Configure logging
    $ipr($id)  setLogLevel 3; # Set log level once
    $phy($id)  enableLog
    #$udp($id)  enableLog
    #$ipif($id) enableLog
    #$mll($id)  enableLog
    #$mac($id)  enableLog



    # Connect L7 -> L6
    for {set target 0} {$target < $opt(nn)} {incr target} {
        if {$id != $target} {
            $node($id) setConnection $cbr($id,$target) $udp($id) 0
        }
    }

    $node($id) setConnection $udp($id)   $ipr($id)  0
    $node($id) setConnection $ipr($id)   $ipif($id) 0
    $node($id) setConnection $ipif($id)  $mll($id)  0
    $node($id) setConnection $mll($id)   $mac($id)  0
    $node($id) setConnection $mac($id)   $phy($id)  0
    $node($id) addToChannel  $channel    $phy($id)  0

    # Assign dynamic listening sockets for mesh traffic
    for {set src 0} {$src < $opt(nn)} {incr src} {
        if {$id != $src} {
            set portnum($src,$id) [$udp($id) assignPort $cbr($id,$src)]
        }
    }

    set tmp_ [expr {$id + 1}]
    $ipif($id) addr $tmp_
    $ipr($id)  addr $tmp_

    # Positioning setup
    set position($id) [new "Position/BM"]
    $node($id) addPosition $position($id)
    set posdb($id) [new "PlugIn/PositionDB"]
    $node($id) addPlugin $posdb($id) 20 "PDB"
    $posdb($id) addpos [$mac($id) addr] $position($id)

    set interf_data($id) [new "Module/UW/INTERFERENCE"]
    $interf_data($id) set maxinterval_ $opt(maxinterval_)
    $interf_data($id) set debug_       0

    $phy($id) setPropagation $propagation
    $phy($id) setSpectralMask $data_mask
    $phy($id) setInterference $interf_data($id)
    $mac($id) initialize
}

#################
# Node Creation #
#################
for {set id 0} {$id < $opt(nn)} {incr id} {
    createNode $id
}

################################
# All-to-All Dynamic Binding
################################
for {set src 0} {$src < $opt(nn)} {incr src} {
    for {set dst 0} {$dst < $opt(nn)} {incr dst} {
        if {$src != $dst} {
            $cbr($src,$dst) set destAddr_ [$ipif($dst) addr]
            $cbr($src,$dst) set destPort_ $portnum($src,$dst)
        }
    }
}

###################
# Populate Mesh ARP
###################
for {set id1 0} {$id1 < $opt(nn)} {incr id1} {
    for {set id2 0} {$id2 < $opt(nn)} {incr id2} {
        if {$id1 != $id2} {
            $mll($id1) addentry [$ipif($id2) addr] [$mac($id2) addr]
        }
    }
}

###############################################
# Node Placement: Geometry Setup
###############################################
set center_x 1000
set center_y 1000
set radius   500
set PI       3.141592653589793

set angle_step [expr {2.0 * $PI / $opt(nn)}]

for {set id 0} {$id < $opt(nn)} {incr id} {
    set current_angle [expr {$id * $angle_step}]
    set x [expr {$center_x + $radius * cos($current_angle)}]
    set y [expr {$center_y + $radius * sin($current_angle)}]

    $position($id) setX_ $x
    $position($id) setY_ $y
    $position($id) setZ_ -100
}

# Setup positions
# for {set id 0} {$id < $opt(nn)} {incr id} {
#     $position($id) setX_ [expr 1000*$id]
#     $position($id) setY_ 0
#     $position($id) setZ_ -100
# }

#####################
# Start/Stop Timers #
#####################
for {set id 0} {$id < $opt(nn)} {incr id} {
    for {set target 0} {$target < $opt(nn)} {incr target} {
        if {$id != $target} {
            $ns at $opt(starttime) "$cbr($id,$target) start"
            $ns at $opt(stoptime)  "$cbr($id,$target) stop"
        }
    }
}

###################
# Final Procedure #
###################
proc get-app-per { tx_app rx_app } {
    set sent_packets [$tx_app getsentpkts]
    set received_packets [$rx_app getrecvpkts]

    if {$sent_packets == 0} { return 0.0 }
    return [expr {1.0 - (1.0 * $received_packets / $sent_packets)}]
}

proc finish {} {
    global ns opt cbr

    puts "---------------------------------------------------------------------"
    puts "All-to-All Dynamic Flooding Simulation (TDMA Base Parameters)"
    puts "Number of Nodes     : $opt(nn)"
    puts "Active Flows        : [expr {$opt(nn) * ($opt(nn) - 1)}]"
    puts "Packet Size         : $opt(pktsize) bytes"
    puts "CBR Period          : $opt(cbr_period) s"
    puts "Bitrate             : $opt(bitrate) bps"
    puts "Tx Power            : $opt(txpower) dB"
    puts "Simulation Duration : $opt(txduration) s"
    puts "---------------------------------------------------------------------"

    set total_throughput  0.0
    set total_sent_pkts   0.0
    set total_rcv_pkts    0.0
    set stream_count      0

    for {set src 0} {$src < $opt(nn)} {incr src} {
        for {set dst 0} {$dst < $opt(nn)} {incr dst} {
            if {$src != $dst} {
                set stream_thr  [$cbr($dst,$src) getthr]
                set stream_sent [$cbr($src,$dst) getsentpkts]
                set stream_rcv  [$cbr($dst,$src) getrecvpkts]
                set stream_per  [get-app-per $cbr($src,$dst) $cbr($dst,$src)]

                if {$opt(verbose)} {
                    puts "Node $src -> Node $dst | Thr: $stream_thr bps | PER: $stream_per | Sent: $stream_sent | Recv: $stream_rcv"
                }

                set total_throughput [expr {$total_throughput + $stream_thr}]
                set total_sent_pkts   [expr {$total_sent_pkts + $stream_sent}]
                set total_rcv_pkts    [expr {$total_rcv_pkts + $stream_rcv}]
                incr stream_count
            }
        }
    }

    puts "---------------------------------------------------------------------"
    puts "Aggregate Network Performance Metrics:"
    puts "Mean Stream Throughput   : [expr {$total_throughput / $stream_count}] bps"
    puts "Total Sent Packets       : $total_sent_pkts"
    puts "Total Received Packets   : $total_rcv_pkts"
    if {$total_sent_pkts > 0} {
        puts "Network Packet Delivery Ratio : [format %.2f [expr {($total_rcv_pkts / $total_sent_pkts) * 100}]] %"
    }
    puts "---------------------------------------------------------------------"

    $ns flush-trace
    if {$opt(trace_files)} {
        close $opt(tracefile)
    }
}

###################
# Start Simulation
###################
$ns at [expr {$opt(stoptime) + 250.0}] "finish; $ns halt"
$ns run
