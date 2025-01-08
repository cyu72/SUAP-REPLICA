from enum import IntEnum
from abc import ABC, abstractmethod
import json

class MESSAGE_TYPE(IntEnum):
    ROUTE_REQUEST = 0
    ROUTE_REPLY = 1
    ROUTE_ERROR = 2
    DATA = 3
    INIT_ROUTE_DISCOVERY = 4
    VERIFY_ROUTE = 5
    HELLO = 6
    INIT_AUTO_DISCOVERY = 7
    EXIT = 8

class MESSAGE(ABC):
    def __init__(self, message_type):
        self.type = message_type

    @abstractmethod
    def serialize(self):
        pass

    @abstractmethod
    def deserialize(self, j):
        pass

class GCS_MESSAGE(MESSAGE):
    def __init__(self, src_addr="NILL", dest_addr="NILL", message_type=MESSAGE_TYPE.DATA):
        super().__init__(message_type)
        self.src_addr = src_addr
        self.dest_addr = dest_addr

    def serialize(self):
        j = {
            "type": int(self.type),  # Convert enum to int
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
        }
        print(json.dumps(j))
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]

class RREQ(MESSAGE):
    def __init__(self, src_addr="", dest_addr="", src_seq_num=0, dest_seq_num=0, hash_value="", hop_count=0, herr=0):
        super().__init__(MESSAGE_TYPE.ROUTE_REQUEST)
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_seq_num = src_seq_num
        self.dest_seq_num = dest_seq_num
        self.hash = hash_value
        self.hop_count = hop_count
        self.HERR = herr

    def serialize(self):
        j = {
            "type": self.type,
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
            "srcSeqNum": self.src_seq_num,
            "destSeqNum": self.dest_seq_num,
            "hash": self.hash,
            "hopCount": self.hop_count,
            "HERR": self.HERR
        }
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]
        self.src_seq_num = data["srcSeqNum"]
        self.dest_seq_num = data["destSeqNum"]
        self.hash = data["hash"]
        self.hop_count = data["hopCount"]
        self.HERR = data["HERR"]

class RREP(MESSAGE):
    def __init__(self, src_addr="", dest_addr="", src_seq_num=0, dest_seq_num=0, hash_value="", hop_count=0, herr=0):
        super().__init__(MESSAGE_TYPE.ROUTE_REPLY)
        self.src_addr = src_addr
        self.dest_addr = dest_addr
        self.src_seq_num = src_seq_num
        self.dest_seq_num = dest_seq_num
        self.hash = hash_value
        self.hop_count = hop_count
        self.HERR = herr

    def serialize(self):
        j = {
            "type": self.type,
            "srcAddr": self.src_addr,
            "destAddr": self.dest_addr,
            "srcSeqNum": self.src_seq_num,
            "destSeqNum": self.dest_seq_num,
            "hash": self.hash,
            "hopCount": self.hop_count,
            "HERR": self.HERR
        }
        return json.dumps(j)

    def deserialize(self, j):
        data = json.loads(j)
        self.type = MESSAGE_TYPE(data["type"])
        self.src_addr = data["srcAddr"]
        self.dest_addr = data["destAddr"]
        self.src_seq_num = data["srcSeqNum"]
        self.dest_seq_num = data["destSeqNum"]
        self.hash = data["hash"]
        self.hop_count = data["hopCount"]
        self.HERR = data["HERR"]