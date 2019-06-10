//
// Created by recolic on 19-6-9.
//

#ifndef UDP_FORWARDER_NG_FORWARDER_HPP
#define UDP_FORWARDER_NG_FORWARDER_HPP

#include <string>
#include <picosha2.h>
#include <rlib/sys/sio.hpp>
#include <sys/epoll.h>
#include <rlib/stdio.hpp>
#include <thread>
#include <Crypto.hpp>
#include <unordered_map>
#include "Config.hpp"
#include "ConnectionTimeoutCtl.hpp"

using std::string;
using namespace std::literals;

inline void epoll_add_fd(fd_t epollFd, fd_t fd) {
    epoll_event event {
        .events = EPOLLIN,
        .data = {
                .fd = fd,
        }
    };
    auto ret1 = epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event);
    if(ret1 == -1)
        throw std::runtime_error("epoll_ctl failed.");
}
inline void epoll_del_fd(fd_t epollFd, fd_t fd) {
    epoll_event event {
        .events = EPOLLIN,
        .data = {
                .fd = fd,
        }
    };
    auto ret1 = epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, &event); // Can be nullptr since linux 2.6.9
    if(ret1 == -1)
        throw std::runtime_error("epoll_ctl failed.");
}

class Forwarder {
public:
    Forwarder(string listenAddr, uint16_t listenPort, string serverAddr, uint16_t serverPort, string lPassword,
              string rPassword)
            : listenAddr(listenAddr), listenPort(listenPort), serverAddr(serverAddr), serverPort(serverPort),
            lKey(picosha2::k_digest_size, '\0'), rKey(picosha2::k_digest_size, '\0') {
        picosha2::hash256(lPassword.begin(), lPassword.end(), lKey.begin(), lKey.end());
        picosha2::hash256(rPassword.begin(), rPassword.end(), rKey.begin(), rKey.end());
        if(lPassword.empty())
            lKey = "";
        if(rPassword.empty())
            rKey = "";
    }

public:
    [[noreturn]] void run() {
        auto listenFd = rlib::quick_listen(listenAddr, listenPort, true);
        rlib_defer([=]{close(listenFd);});

        auto epollFd = epoll_create1(0);
        if(epollFd == -1)
            throw std::runtime_error("Failed to create epoll fd.");
        epoll_add_fd(epollFd, listenFd);

        epoll_event events[MAX_EVENTS];

        char buffer[DGRAM_BUFFER_SIZE];
        // WARN: If you want to modify this program to work for both TCP and UDP, PLEASE use rlib::sockIO::recv instead of fixed buffer.

        // Map from serverSession to clientSession.
        // If I see a packet from client, throw it to server.
        // If I see a packet from server, I have to determine which client to throw it.
        // So I have to record the map between client and server, one-to-one.
        struct clientInfo {
            sockaddr_storage addr; socklen_t len;
            bool operator==(const clientInfo &another) const {
                if(len != another.len) return false;
                return std::memcmp(&addr, &another.addr, len) == 0;
            }
            bool isNull() const {
                for(auto cter = 0; cter < sizeof(addr); ++cter) {
                    if(cter[(char *)&addr] != 0)
                        return false;
                }
                return true;
            }
        } __attribute__((packed));
        struct clientInfoHash {std::size_t operator()(const clientInfo &info) const {return *(std::size_t*)&info.addr;}}; // hash basing on port number and part of ip (v4/v6) address.
        std::unordered_map<clientInfo, fd_t, clientInfoHash> client2server;
        std::unordered_map<fd_t, clientInfo> server2client;
        std::unordered_map<fd_t, size_t> server2wallTime;
        // If connection creation time is less than walltime, the connection timed out.

        auto connForNewClient = [&, this](const clientInfo &info) {
            if(info.isNull()) throw std::runtime_error("Invalid client info");
            auto serverFd = rlib::quick_connect(serverAddr, serverPort, true);
            rlib::println("creating new connection...");
            client2server[info] = serverFd; // May overwrite existing element on server timing out.
            server2client.insert(std::make_pair(serverFd, info));
            server2wallTime.insert(std::make_pair(serverFd, getWallTime()));
            epoll_add_fd(epollFd, serverFd);
            return serverFd;
        };
        auto eraseServerConn = [&](fd_t fd) {
            server2client.erase(fd);
            server2wallTime.erase(fd);
            epoll_del_fd(epollFd, fd);
        };

        rlib::println("Forwarding server working...");

        // Main loop!
        while(true) {
            auto nfds = epoll_wait(epollFd, events, MAX_EVENTS, -1);
            if(nfds == -1)
                throw std::runtime_error("epoll_wait failed.");

            for(auto cter = 0; cter < nfds; ++cter) {
                const auto recvFd = events[cter].data.fd;
                const auto recvSideIsClientSide = server2client.find(recvFd) == server2client.end(); // is not server
                const auto &recvSideKey = recvSideIsClientSide ? lKey : rKey;
                const auto &sendSideKey = recvSideIsClientSide ? rKey : lKey;

                try {
                    size_t size;
                    fd_t anotherFd;
                    sockaddr *sendtoAddr = nullptr;
                    socklen_t sendtoAddrLen = 0;
                    clientInfo clientSideInfo;
                    // Recv /////////////////////////////////////////////////////////////////////////////////////
                    if(recvSideIsClientSide) {
                        // Client to Server packet.
                        auto &info = clientSideInfo;
                        size = recvfrom(recvFd, buffer, DGRAM_BUFFER_SIZE, 0, (sockaddr *)&info.addr, &info.len);
                        if(size == -1)
                            throw std::runtime_error("ERR: recvfrom returns -1. "s + strerror(errno));
                        auto pos = client2server.find(info);
                        if(pos == client2server.end())
                            anotherFd = connForNewClient(info);
                        else
                            anotherFd = pos->second;
                    }
                    else {
                        // Server to Client packet.
                        size = recvfrom(recvFd, buffer, DGRAM_BUFFER_SIZE, 0, nullptr, nullptr);
                        if(size == -1)
                            throw std::runtime_error("ERR: recvfrom returns -1. "s + strerror(errno));
                        clientInfo &info = server2client.at(recvFd); // If server not found, drop the msg. (The server may just timed out)
                        sendtoAddr = (sockaddr *)&info.addr;
                        sendtoAddrLen = info.len;
                        anotherFd = listenFd;
                        clientSideInfo = info;
                    }

                    // received raw data.
                    string bufferStr (std::begin(buffer), std::begin(buffer) + size);

                    // Addon: ConnTimeout ///////////////////////////////////////////////////////////////////////////
                    // Recolic: The GFW use deep-packet-inspection to fuck my OpenVPN connection in about 10 minutes.
                    //   What if I change a new connection in every 1 minute?
                    //   Try it.

                    if(bufferStr.size() >= sizeof(uint64_t)) {
                        // Check control msg. Its nonce is zero.
                        if(*(uint64_t*)bufferStr.data() == 0) {
                            if(recvSideIsClientSide) {
                                // ctl msg from client. (conn change req)
                                if(bufferStr.size() < sizeof(uint64_t) + 2*sizeof(clientInfo))
                                    throw std::runtime_error("ctl msg from client too short.");
                                clientInfo previous, newOne;
                                std::memcpy(&previous, bufferStr.data()+sizeof(uint64_t), sizeof(clientInfo));
                                std::memcpy(&newOne, bufferStr.data()+sizeof(uint64_t)+sizeof(clientInfo), sizeof(clientInfo));
                                previous.len = be32toh(previous.len); newOne.len = be32toh(newOne.len);

                                auto iter = client2server.find(previous);
                                if(iter == client2server.end())
                                    throw std::runtime_error("ctl msg from client: change conn: prev conn not exist.");
                                auto serverFd = iter->second;
                                server2client[serverFd] = newOne;
                                client2server[newOne] = serverFd;

                                // send ACK to client(recvFd)
                                string ackStr (sizeof(uint64_t), '\0');
                                auto ret = sendto(recvFd, ackStr.data(), ackStr.size(), 0, (sockaddr*)&previous.addr, previous.len);
                                if(ret == -1)
                                    throw std::runtime_error("Failed to send CONN CHANGE ACK");

                                // remove the ctl prefix
                                bufferStr = bufferStr.substr(sizeof(uint64_t) + 2*sizeof(clientInfo));
                            }
                            else {
                                // ctl msg from server (conn change ack)
                                if(bufferStr.size() != sizeof(uint64_t))
                                    throw std::runtime_error("wrong ack ctl from server");
                                server2client.erase(recvFd);
                                server2wallTime.erase(recvFd);
                                continue; // nothing todo with bare ACK.
                            }
                        }
                    }

                    // Encrypt/Decrypt ///////////////////////////////////////////////////////////////////////////////
                    crypto.convertL2R(bufferStr, recvSideKey, sendSideKey);
                    // Encrypt/Decrypt End. Continue ConnTimeout Addon ///////////////////////////////////////////////

                    auto prepareConnChangeReq = [&](fd_t prevFd, fd_t newFd) {
                        clientInfo previous, newOne;
                        auto ret = getsockname(prevFd, (sockaddr*)&previous.addr, &previous.len) +
                                getsockname(newFd, (sockaddr*)&newOne.addr, &newOne.len);
                        if(ret != 0)
                            throw std::runtime_error("getsockname failed.");
                        previous.len = htobe32(previous.len); newOne.len = htobe32(newOne.len);

                        // Add control header.
                        bufferStr = string(sizeof(uint64_t) + sizeof(clientInfo)*2, '\0') + bufferStr;
                        std::memcpy((char*)bufferStr.data()+sizeof(uint64_t), &previous, sizeof(clientInfo));
                        std::memcpy((char*)bufferStr.data()+sizeof(uint64_t)+sizeof(clientInfo), &newOne, sizeof(clientInfo));
                    };

                    if(recvSideIsClientSide && !sendSideKey.empty()) {
                        // Check server connection timeout.
                        // Only timeout the connection if server-side is encrypted. Or OpenVPN server will confuse.
                        // If the connection is timeout:
                        //   1. Create the new connection, reset timeout, update client2server and insert server2client.
                        //   2. Attach the control header onto the origin data packet, send it on the new connection.
                        // When received message from server, if server2client doesn't match client2server, meaning
                        //   that this connection is already timed out.
                        //   If the message is ACK control message, remove the old entry in server2client.
                        //   Otherwise, resend the bare control header in previous step 2.
                        if(server2wallTime.at(anotherFd) < getWallTime()) {
                            // This connection timed out. TODO: Check if creating new connection is slow.
                            auto newConnFd = connForNewClient(clientSideInfo);
                            prepareConnChangeReq(anotherFd, newConnFd);
                       }
                    }

                    if(!recvSideIsClientSide) {
                        // server to client: check if the server missed my req.
                        auto clientOwnerFd = client2server.at(server2client.at(recvFd));
                        if(clientOwnerFd != recvFd) {
                            // Client2server already modified, but not receiving ACK.
                            // resend.
                            prepareConnChangeReq(recvFd, clientOwnerFd);
                        }
                    }

                    // Send /////////////////////////////////////////////////////////////////////////////////////
                    if(recvSideIsClientSide) {
                        // Client to Server packet.
                        size = send(anotherFd, bufferStr.data(), bufferStr.size(), 0);
                    }
                    else {
                        // Server to Client packet.
                        size = sendto(anotherFd, bufferStr.data(), bufferStr.size(), 0, sendtoAddr, sendtoAddrLen);
                    }
                    if(size == -1) {
                        throw std::runtime_error("ERR: sendto returns -1. "s + strerror(errno));
                    }
                    if(size != bufferStr.size()) {
                        rlib::println("WARN: sendto not sent all data.");
                    }
                    // Done /////////////////////////////////////////////////////////////////////////////////////
                }
                catch(std::exception &e) {
                    rlib::println(e.what());
                }
            }
        }
    }


private:
    string listenAddr;
    uint16_t listenPort;
    string serverAddr;
    uint16_t serverPort;
    string lKey;
    string rKey;
    Crypto crypto;
};


#endif //UDP_FORWARDER_NG_FORWARDER_HPP
