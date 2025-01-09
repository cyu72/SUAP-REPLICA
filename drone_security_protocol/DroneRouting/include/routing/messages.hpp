#ifndef MESSAGES_HPP
#define MESSAGES_HPP
#include <string>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <netdb.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <chrono>
#include <vector>
#include <algorithm>

using json = nlohmann::json;
using std::cout;
using std::endl;
using std::string;

enum MESSAGE_TYPE {
    ROUTE_REQUEST = 0,
    ROUTE_REPLY, 
    ROUTE_ERROR,
    DATA,
    CERTIFICATE_VALIDATION,
    LEAVE_NOTIFICATION,
    INIT_ROUTE_DISCOVERY, // Everything below here is not apart of the actual protocol
    VERIFY_ROUTE,
    HELLO, // Broadcast Msg
    INIT_AUTO_DISCOVERY,
    EXIT
};

struct MESSAGE {
    MESSAGE_TYPE type;
    virtual string serialize() const = 0;
    virtual void deserialize(json& j) = 0;
    virtual ~MESSAGE() = default;
};

struct GCS_MESSAGE : public MESSAGE { // used as a means to send gcs msgs
    std::string srcAddr;
    std::string destAddr;

    GCS_MESSAGE() {
        this->type = DATA;
        this->srcAddr = "NILL";
        this->destAddr = "NILL";
    }

    GCS_MESSAGE(std::string srcAddr, std::string destAddr, std::string msg) {
        this->type = DATA;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
    }

    std::string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
    }
};

struct RERR : public MESSAGE {
    std::vector<string> nonce_list;
    std::vector<string> tsla_list;
    std::vector<string> dst_list;
    std::vector<string> auth_list;
    std::string retAddr; // Temp

    RERR() {
        this->type = ROUTE_ERROR;
    }

    RERR(std::vector<string> nonce_list, std::vector<string> tsla_list, std::vector<string> dst_list, std::vector<string> auth_list) {
        this->type = ROUTE_ERROR;
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr(const std::vector<string>& nonce_list, 
                            const std::vector<string>& tsla_list, 
                            const std::vector<string>& dst_list, 
                            const std::vector<string>& auth_list) {
        this->type = ROUTE_ERROR;
        this->nonce_list = nonce_list;
        this->tsla_list = tsla_list;
        this->dst_list = dst_list;
        this->auth_list = auth_list;
    }

    void create_rerr(const string& nonce, const string& tsla_nonce, const string& dst, const string& auth) {
        this->type = ROUTE_ERROR;
        this->nonce_list = {nonce};
        this->tsla_list = {tsla_nonce};
        this->dst_list = {dst};
        this->auth_list = {auth};
    }

    void addRetAddr(const string& addr){
        this->retAddr = addr;
    }

    void create_rerr_prime(const string& nonce, const string& dst, const string& auth) {
        this->type = ROUTE_ERROR;
        this->nonce_list = {nonce};
        this->tsla_list = {};  // Empty for RERR'
        this->dst_list = {dst};
        this->auth_list = {auth};
    }

    string serialize() const {
        json j = json::object();
        j["auth_list"] = this->auth_list;
        j["dst_list"] = this->dst_list;
        j["nonce_list"] = this->nonce_list;
        j["retAddr"] = this->retAddr;
        j["tsla_list"] = this->tsla_list;
        j["type"] = this->type;
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->nonce_list = j["nonce_list"].get<std::vector<string>>();
        this->tsla_list = j["tsla_list"].get<std::vector<string>>();
        this->dst_list = j["dst_list"].get<std::vector<string>>();
        this->auth_list = j["auth_list"].get<std::vector<string>>();
        this->retAddr = j["retAddr"];
    }
};

struct RREQ : public MESSAGE {
    string srcAddr;
    string recvAddr; // temp field used to store next hop addr, since we are using services, cannnot directly extract last recieved ip
    string destAddr; 
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    string rootHash;
    unsigned long hopCount;
    int ttl; // Max number of hops allowed for RREQ to propagate through network

    RREQ() {
        this->type = ROUTE_REQUEST;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->rootHash = "";
        this->ttl = 0;
    }

    RREQ(string srcAddr, string interAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, 
         string hash, unsigned long hopCount, int ttl, string rootHash) {
        this->type = ROUTE_REQUEST;
        this->srcAddr = srcAddr;
        this->recvAddr = interAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->ttl = ttl;
        this->rootHash = rootHash;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"recvAddr", this->recvAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"ttl", this->ttl},
            {"rootHash", this->rootHash},
        };

        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->recvAddr = j["recvAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->ttl = j["ttl"];
        this->rootHash = j["rootHash"];
    }
};

struct RREP : public MESSAGE {
    string srcAddr;
    string recvAddr; // same temp field as RREQ
    string destAddr;
    unsigned long srcSeqNum;
    unsigned long destSeqNum;
    string hash;
    unsigned long hopCount;
    int ttl;

    RREP() {
        this->type = ROUTE_REPLY;
        this->srcSeqNum = 0;
        this->destSeqNum = 0;
        this->hash = "";
        this->hopCount = 0;
        this->ttl = 0;
    }

    RREP(string srcAddr, string destAddr, unsigned long srcSeqNum, unsigned long destSeqNum, string hash, unsigned long hopCount, int ttl) {
        this->type = ROUTE_REPLY;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->srcSeqNum = srcSeqNum;
        this->destSeqNum = destSeqNum;
        this->hash = hash;
        this->hopCount = hopCount;
        this->ttl = ttl;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"recvAddr", this->recvAddr},
            {"srcSeqNum", this->srcSeqNum},
            {"destSeqNum", this->destSeqNum},
            {"hash", this->hash},
            {"hopCount", this->hopCount},
            {"ttl", this->ttl}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
        this->destAddr = j["destAddr"];
        this->recvAddr = j["recvAddr"];
        this->srcSeqNum = j["srcSeqNum"];
        this->destSeqNum = j["destSeqNum"];
        this->hash = j["hash"];
        this->hopCount = j["hopCount"];
        this->ttl = j["ttl"];
    }

};

struct INIT_MESSAGE : public MESSAGE { // Can possibly collapse this in the future with TESLA_MESSAGE
    string srcAddr;

    INIT_MESSAGE() {
        this->type = HELLO;
        srcAddr = "";
    }

    INIT_MESSAGE(string addr) {
        this->type = HELLO;
        this->srcAddr = addr;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"srcAddr", this->srcAddr}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->srcAddr = j["srcAddr"];
    }
    
};

struct DATA_MESSAGE : public MESSAGE {
    bool isBroadcast;
    string destAddr;
    string srcAddr;
    string data;

    DATA_MESSAGE() {
        isBroadcast = false;
        this->type = DATA;
        this->destAddr = "";
        this->data = "";
    }

    DATA_MESSAGE(string destAddr, string srcAddr, string data, bool isBroadcast = false) {
        this->isBroadcast = isBroadcast;
        this->type = DATA;
        this->srcAddr = srcAddr;
        this->destAddr = destAddr;
        this->data = data;
    }

    string serialize() const override {
        json j = json{
            {"type", this->type},
            {"isBroadcast", this->isBroadcast},
            {"srcAddr", this->srcAddr},
            {"destAddr", this->destAddr},
            {"data", this->data}
        };
        return j.dump();
    }

    void deserialize(json& j) override {
        this->type = j["type"];
        this->isBroadcast = j["isBroadcast"];
        this->destAddr = j["destAddr"];
        this->srcAddr = j["srcAddr"];
        this->data = j["data"];
    }
};

#endif