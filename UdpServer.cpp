//------------------------------------------------------------------------------------------
//     Copyright (c)2005-2010 PPLive Corporation.  All rights reserved.
//------------------------------------------------------------------------------------------

#include <protocol/UdpServer.h>
#include <util/buffers/SubBuffers.h>
#include <util/buffers/BufferCopy.h>

#include <framework/system/BytesOrder.h>
#include <framework/logger/Logger.h>
#include <framework/logger/LoggerStreamRecord.h>
using namespace framework::logger;

#include <boost/bind.hpp>
#include <boost/ref.hpp>
#include <boost/asio/placeholders.hpp>

#include "protocol/CheckSum.h"

namespace protocol
{
    FRAMEWORK_LOGGER_DECLARE_MODULE("UdpServer");

    inline boost::uint32_t read_uint32(
        boost::uint32_t const *& buf,
        boost::uint32_t & vt,
        boost::uint8_t nl,
        boost::uint8_t nr)
    {
        boost::uint32_t v = vt;
        vt = *buf++;
#ifdef BOOST_BIG_ENDIAN
        return (v << nl) | (vt >> nr);
#else
        return (v >> nl) | (vt << nr);
#endif
    }

    inline boost::uint32_t move_right(
        boost::uint32_t vt,
        boost::uint8_t n)
    {
#ifdef BOOST_BIG_ENDIAN
        return vt >> n;
#else
        return vt << n;
#endif
    }

    inline boost::uint32_t move_left(
        boost::uint32_t vt,
        boost::uint8_t n)
    {
#ifdef BOOST_BIG_ENDIAN
        return vt << n;
#else
        return vt >> n;
#endif
    }

#ifdef BOOST_BIG_ENDIAN
#  define MOVE_LEFT(vt, n) (vt << n)
#  define MOVE_RIGHT(vt, n) (vt >> n)
#  define LEFT_MOST_BYTE(vt) (vt >> 24)
#else
#  define MOVE_LEFT(vt, n) (vt >> n)
#  define MOVE_RIGHT(vt, n) (vt << n)
#  define LEFT_MOST_BYTE(vt) (vt & 0x000000FF)
#endif

#define GET(v) \
    vt1 = *buf++; \
    v = MOVE_LEFT(vt0, nl) | MOVE_RIGHT(vt1, nr); \
    vt0 = vt1

    UdpServer::UdpServer(
        boost::asio::io_service & io_svc,
        IUdpServerListener::p handler)
        : boost::asio::ip::udp::socket(io_svc)
        , handler_(handler)
        , port_(0)
        , minimal_protocol_version_(0)
    {
    }

    bool UdpServer::Listen(
        boost::uint16_t port)
    {
        boost::system::error_code error;
        open(boost::asio::ip::udp::v4(), error);
        if (error) {
            return false;
        }
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), port);
        bind(ep, error);
        if (error) {
            close(error);
            return false;
        }
        port_ = port;

        return true;
    }

    boost::uint32_t UdpServer::Recv(
        boost::uint32_t count)
    {
        boost::uint32_t i = 0;
        for (; i < count; ++i) {
            UdpBuffer * recv_buffer = new UdpBuffer;
            if (!recv_buffer) {
                break;
            }

            if (!*recv_buffer) {
                delete recv_buffer;
                recv_buffer = NULL;
                break;
            }

            UdpRecvFrom(*recv_buffer);
        }
        return i;
    }

    void UdpServer::UdpRecvFrom(
        UdpBuffer & recv_buffer)
    {
        async_receive_from(
            recv_buffer.prepare(),
            recv_buffer.end_point(),
            boost::bind(&UdpServer::HandleUdpRecvFrom,
                ref_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred,
                boost::ref(recv_buffer)));
    }

    void UdpServer::UdpSendTo(
        const UdpBuffer & send_buffer, 
        boost::uint16_t dest_protocol_version)
    {
        // check sum
        boost::uint32_t & chk_sum = const_cast<boost::uint32_t &>(
            *boost::asio::buffer_cast<boost::uint32_t const *>(*send_buffer.data().begin()));

        if (dest_protocol_version < PEER_VERSION_V5)
        {
            chk_sum = check_sum_old(util::buffers::sub_buffers(send_buffer.data(), 4));
        }
        else
        {
            chk_sum = check_sum_new(util::buffers::sub_buffers(send_buffer.data(), 4));
        }

        // send
        boost::system::error_code ec;
        send_to(send_buffer.data(), send_buffer.end_point(), 0, ec);
    }

    void UdpServer::HandleUdpRecvFrom(
        boost::system::error_code const & error,
        boost::uint32_t bytes_transferred,
        UdpBuffer & recv_buffer)
    {
        if (!handler_) {
            delete &recv_buffer;
            return;
        }

        if (!error && bytes_transferred > sizeof(boost::uint32_t) + sizeof(boost::uint8_t)) {
            recv_buffer.commit(bytes_transferred);
            boost::uint32_t chk_sum;
            IUdpBufferStream is(&recv_buffer);
            is.read((boost::uint8_t *)&chk_sum, sizeof(boost::uint32_t));

            boost::uint8_t action = is.get();
            std::map<boost::uint8_t, packet_handler_type>::const_iterator iter =
                packet_handlers_.find(action);
            if (iter != packet_handlers_.end())
            {
                boost::uint16_t protocol_version;
                if (get_protocol_version(recv_buffer, bytes_transferred-5, action, protocol_version))
                {
                    is.unget(); // 将action放回Buffer中
                    if (verify_check_sum(recv_buffer, chk_sum, protocol_version)) 
                    {
                        is.get(); // 将action从Buffer中读出，下面的handle函数只序列化action后面的字段
                        (this->*iter->second)(recv_buffer);
                    }
                }                
            }
            else 
            {
                LOG_S(Logger::kLevelAlarm, "HandleUdpRecvFrom: unknown action " << action);
            }
        }
        recv_buffer.reset();
        UdpRecvFrom(recv_buffer);
    }

    bool UdpServer::get_protocol_version(UdpBuffer & buffer, boost::uint32_t bytes_left,
        boost::uint8_t action, boost::uint16_t & protocol_version)
    {
        IUdpBufferStream is(&buffer);
        IUdpArchive ia(buffer);
        if (action >= 0x50 && action < 0x60)
        {
            // 处理PeerPacket协议族
            if (bytes_left < 6)
            {
                return false;
            }

            is.ignore(4);
            ia >> protocol_version;
            for (int i = 0; i < 6; ++i)
            {
                is.unget();
            }
        }
        else if (action >= 0xA0 && action < 0xB0)
        {
            // 处理notify协议族，没有协议版本域都是使用PEER_VERSION_V4计算校验和
            protocol_version = protocol::PEER_VERSION_V4;
        }
        else
        {
            if (bytes_left < 5)
            {
                return false;
            }

            is.ignore(4);
            boost::uint8_t is_request = is.get();

            if (is_request)
            {
                if (bytes_left < 7)
                {
                    return false;
                }

                ia >> protocol_version;
                is.unget();
                is.unget();
            }
            else
            {
                protocol_version = protocol::PEER_VERSION;
            }

            for (int i = 0; i < 5; i++)
            {
                is.unget();
            }
        }

        return true;
    }

    bool UdpServer::verify_check_sum(UdpBuffer & buffer, boost::uint32_t chk_sum,
        boost::uint16_t protocol_version)
    {
        if (protocol_version >= minimal_protocol_version_)
        {
            if (protocol_version >= PEER_VERSION_V5)
            {
                return (check_sum_new(buffer.data()) == chk_sum);
            }
            else
            {
                return (check_sum_old(buffer.data()) == chk_sum);
            }
        }
        else
        {
            return false;
        }
    }

    void UdpServer::Close()
    {
        boost::system::error_code error;
        close(error);
        handler_ = NULL;
    }
}
