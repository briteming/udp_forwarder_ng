//
// Created by recolic on 19-6-10.
//

#ifndef UDP_FORWARDER_NG_CONNECTIONTIMEOUTCTL_HPP
#define UDP_FORWARDER_NG_CONNECTIONTIMEOUTCTL_HPP


#include <cstddef>
#include <rlib/sys/fd.hpp>

inline size_t getWallTime() {
    return 0;

}

// Change connection to encrypted server in every 1 minute to avoid GFW deep-packet-inspect.
class ConnectionTimeoutCtl {
public:
    ConnectionTimeoutCtl(size_t timeoutSeconds, bool serverSideIsEncrypted)
    : timeoutSeconds(timeoutSeconds), serverSideIsEncrypted(serverSideIsEncrypted) {
        // If server side is unencrypted, set timeout to +inf.
    }

    bool encryptedMessageIsControlMessage() {
        // Client side operation.
        // 1. Return true if the message is control message (nonce=0)
        // 2. if the message is control msg, deal with it.
    }

    fd_t shouldChangeConnection() {
        // Server side operation.
        // 1. Return new fd ONLY if the connection should time out AND the new connection is ready.
        //      else return -1.
        // 2. This function should send the control message, and update the client2server map.
    }





private:
    size_t timeoutSeconds;
    bool serverSideIsEncrypted;
};


#endif //UDP_FORWARDER_NG_CONNECTIONTIMEOUTCTL_HPP
