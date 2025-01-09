#pragma once
#include <iostream>
#include <tuple>
#include <chrono>
#include <queue>
#include "messages.hpp"

using std::string;
using std::cout;
using std::endl;

struct ROUTING_TABLE_ENTRY {
    string destAddr;
    string intermediateAddr; // srcAddr = destAddr if neighbor
    int seqNum; // Destination SeqNum
    int cost; // HopCount to reach destination
    std::chrono::system_clock::time_point ttl; // Starting Timestamp at which this entry was created

    ROUTING_TABLE_ENTRY(){
        this->destAddr = "ERR";
        this->intermediateAddr = "ERR";
        this->seqNum = -1;
        this->cost = -1;
        this->ttl = std::chrono::system_clock::now(); // Starting Timestamp at which this entry was created
    }

    // TODO: Must fix all instances of ttl
    ROUTING_TABLE_ENTRY(string destAddr, string intermediateAddr, int seqNum, int cost, std::chrono::system_clock::time_point ttl){
        this->destAddr = destAddr;
        this->intermediateAddr = intermediateAddr;
        this->seqNum = seqNum;
        this->cost = cost;
        this->ttl = ttl;
    }

    void print() const {
        auto ttl_seconds = std::chrono::duration_cast<std::chrono::seconds>(ttl.time_since_epoch()).count();
        cout << "Routing entry: " << "destAddr: " << destAddr << ", intermediateAddr: " << intermediateAddr << ", seqNum: " << seqNum << ", cost: " << cost << ", ttl: " << ttl_seconds << " seconds ";
        
        cout << endl;
    }

    friend std::ostream& operator<<(std::ostream& os, const ROUTING_TABLE_ENTRY& entry) {
        os << "{ destAddr: " << entry.destAddr << ", intermediateAddr: " << entry.intermediateAddr
           << ", seqNum: " << entry.seqNum << ", cost: " << entry.cost
           << ", ttl: " << std::chrono::duration_cast<std::chrono::seconds>(entry.ttl.time_since_epoch()).count() << " seconds, hash: " << " }";
        return os;
    }
};
