#ifndef HYCONNECT_NOISE_SESSION_H
#define HYCONNECT_NOISE_SESSION_H

#include <QByteArray>
#include "noise.h"

struct NoiseCipherState_s;
struct NoiseHandshakeState_s;
typedef struct NoiseCipherState_s NoiseCipherState;
typedef struct NoiseHandshakeState_s NoiseHandshakeState;

class NoiseSession
{
public:
    NoiseSession()
        : m_handshake(0),
          m_sendCipher(0),
          m_receiveCipher(0),
          m_ready(false)
    {
    }
    ~NoiseSession()
    {
        Reset();
    }

    bool InitializeInitiator(const QByteArray &serverStaticPub)
    {
        Reset();

        if (serverStaticPub.size() != 32)
            return false;

        if (noise_handshakestate_new_by_name(
                &m_handshake, kNoiseProtocolName, NOISE_ROLE_INITIATOR) !=
            NOISE_ERROR_NONE)
        {
            Reset();
            return false;
        }

        NoiseDHState *remoteStatic =
            noise_handshakestate_get_remote_public_key_dh(m_handshake);
        if (!remoteStatic ||
            noise_dhstate_set_public_key(
                remoteStatic,
                reinterpret_cast<const uint8_t *>(serverStaticPub.constData()),
                static_cast<size_t>(serverStaticPub.size())) != NOISE_ERROR_NONE ||
            noise_handshakestate_start(m_handshake) != NOISE_ERROR_NONE)
        {
            Reset();
            return false;
        }

        return true;
    }
    bool InitializeResponder(const QByteArray &serverStaticPriv)
    {
        Reset();

        if (serverStaticPriv.size() != 32)
            return false;

        if (noise_handshakestate_new_by_name(
                &m_handshake, kNoiseProtocolName, NOISE_ROLE_RESPONDER) !=
            NOISE_ERROR_NONE)
        {
            Reset();
            return false;
        }

        NoiseDHState *localStatic =
            noise_handshakestate_get_local_keypair_dh(m_handshake);
        if (!localStatic ||
            noise_dhstate_set_keypair_private(
                localStatic,
                reinterpret_cast<const uint8_t *>(serverStaticPriv.constData()),
                static_cast<size_t>(serverStaticPriv.size())) != NOISE_ERROR_NONE ||
            noise_handshakestate_start(m_handshake) != NOISE_ERROR_NONE)
        {
            Reset();
            return false;
        }

        return true;
    }
    bool WriteHandshakeMessage(QByteArray &outBuffer)
    {
        if (!m_handshake ||
            noise_handshakestate_get_action(m_handshake) !=
                NOISE_ACTION_WRITE_MESSAGE)
        {
            return false;
        }

        QByteArray messageData(kMaxHandshakeMessageSize, '\0');
        NoiseBuffer message;
        noise_buffer_set_output(
            message,
            reinterpret_cast<uint8_t *>(messageData.data()),
            static_cast<size_t>(messageData.size()));

        if (noise_handshakestate_write_message(m_handshake, &message, 0) !=
            NOISE_ERROR_NONE)
        {
            return false;
        }

        messageData.resize(static_cast<int>(message.size));
        outBuffer = messageData;
        return splitIfReady();
    }
    bool ReadHandshakeMessage(const QByteArray &inBuffer)
    {
        if (!m_handshake ||
            noise_handshakestate_get_action(m_handshake) != NOISE_ACTION_READ_MESSAGE)
        {
            return false;
        }

        QByteArray messageData = inBuffer;
        NoiseBuffer message;
        noise_buffer_set_input(
            message,
            reinterpret_cast<uint8_t *>(messageData.data()),
            static_cast<size_t>(messageData.size()));

        if (noise_handshakestate_read_message(m_handshake, &message, 0) !=
            NOISE_ERROR_NONE)
        {
            return false;
        }

        return splitIfReady();
    }
    bool Encrypt(const QByteArray &plaintext, QByteArray &ciphertext)
    {
        if (!m_ready || !m_sendCipher)
            return false;

        const size_t macLen = noise_cipherstate_get_mac_length(m_sendCipher);
        QByteArray buffer = plaintext;
        buffer.resize(buffer.size() + static_cast<int>(macLen));

        NoiseBuffer payload;
        noise_buffer_set_inout(
            payload,
            reinterpret_cast<uint8_t *>(buffer.data()),
            static_cast<size_t>(plaintext.size()),
            static_cast<size_t>(buffer.size()));

        if (noise_cipherstate_encrypt(m_sendCipher, &payload) != NOISE_ERROR_NONE)
            return false;

        buffer.resize(static_cast<int>(payload.size));
        ciphertext = buffer;
        return true;
    }
    bool Decrypt(const QByteArray &ciphertext, QByteArray &plaintext)
    {
        if (!m_ready || !m_receiveCipher)
            return false;

        QByteArray buffer = ciphertext;
        NoiseBuffer payload;
        noise_buffer_set_inout(
            payload,
            reinterpret_cast<uint8_t *>(buffer.data()),
            static_cast<size_t>(buffer.size()),
            static_cast<size_t>(buffer.size()));

        if (noise_cipherstate_decrypt(m_receiveCipher, &payload) != NOISE_ERROR_NONE)
            return false;

        buffer.resize(static_cast<int>(payload.size));
        plaintext = buffer;
        return true;
    }
    bool isReady() const { return m_ready; }
    void Reset()
    {
        m_ready = false;

        if (m_sendCipher)
        {
            noise_cipherstate_free(m_sendCipher);
            m_sendCipher = 0;
        }

        if (m_receiveCipher)
        {
            noise_cipherstate_free(m_receiveCipher);
            m_receiveCipher = 0;
        }

        if (m_handshake)
        {
            noise_handshakestate_free(m_handshake);
            m_handshake = 0;
        }
    }

private:
    inline static constexpr char kNoiseProtocolName[] =
        "Noise_NK_25519_ChaChaPoly_SHA256";
    inline static const int kMaxHandshakeMessageSize = 512;

    bool splitIfReady()
    {
        if (!m_handshake)
            return false;

        const int action = noise_handshakestate_get_action(m_handshake);
        if (action == NOISE_ACTION_SPLIT)
        {
            if (noise_handshakestate_split(
                    m_handshake, &m_sendCipher, &m_receiveCipher) != NOISE_ERROR_NONE)
            {
                Reset();
                return false;
            }

            m_ready = true;
            return true;
        }

        return action == NOISE_ACTION_READ_MESSAGE ||
               action == NOISE_ACTION_WRITE_MESSAGE ||
               action == NOISE_ACTION_COMPLETE;
    }

    NoiseHandshakeState *m_handshake;
    NoiseCipherState *m_sendCipher;
    NoiseCipherState *m_receiveCipher;
    bool m_ready;
};

#endif // HYCONNECT_NOISE_SESSION_H
