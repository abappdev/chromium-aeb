// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_POLICY_NOISE_SESSION_H_
#define CHROME_BROWSER_POLICY_NOISE_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <string>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "noise.h"

struct NoiseCipherState_s;
struct NoiseHandshakeState_s;
typedef struct NoiseCipherState_s NoiseCipherState;
typedef struct NoiseHandshakeState_s NoiseHandshakeState;

namespace policy {

class NoiseSession {
public:
  NoiseSession() = default;
  NoiseSession(const NoiseSession &) = delete;
  NoiseSession &operator=(const NoiseSession &) = delete;
  ~NoiseSession() { Reset(); }

  bool InitializeInitiator(const std::array<uint8_t, 32> &server_static_pub) {
    Reset();

    NoiseHandshakeState *handshake = nullptr;
    if (noise_handshakestate_new_by_name(&handshake, kNoiseProtocolName,
                                         NOISE_ROLE_INITIATOR) !=
        NOISE_ERROR_NONE) {
      Reset();
      return false;
    }
    handshake_ = handshake;

    NoiseDHState *remote_static =
        noise_handshakestate_get_remote_public_key_dh(handshake_);
    if (!remote_static ||
        noise_dhstate_set_public_key(remote_static, server_static_pub.data(),
                                     server_static_pub.size()) !=
            NOISE_ERROR_NONE ||
        noise_handshakestate_start(handshake_) != NOISE_ERROR_NONE) {
      Reset();
      return false;
    }

    return true;
  }

  bool WriteHandshakeMessage(std::string *out_buffer) {
    if (!handshake_ || !out_buffer ||
        noise_handshakestate_get_action(handshake_) !=
            NOISE_ACTION_WRITE_MESSAGE) {
      return false;
    }

    std::array<uint8_t, kMaxHandshakeMessageSize> message_data;
    NoiseBuffer message;
    noise_buffer_set_output(message, message_data.data(), message_data.size());

    if (noise_handshakestate_write_message(handshake_, &message, nullptr) !=
        NOISE_ERROR_NONE) {
      return false;
    }

    out_buffer->assign(reinterpret_cast<const char *>(message.data),
                       message.size);
    return SplitIfReady();
  }

  bool ReadHandshakeMessage(const std::string &in_buffer) {
    if (!handshake_ || noise_handshakestate_get_action(handshake_) !=
                           NOISE_ACTION_READ_MESSAGE) {
      return false;
    }

    std::vector<uint8_t> message_data(in_buffer.begin(), in_buffer.end());
    NoiseBuffer message;
    noise_buffer_set_input(message, message_data.data(), message_data.size());

    if (noise_handshakestate_read_message(handshake_, &message, nullptr) !=
        NOISE_ERROR_NONE) {
      return false;
    }

    return SplitIfReady();
  }

  bool Encrypt(const std::string &plaintext, std::string *ciphertext) {
    if (!ready_ || !send_cipher_ || !ciphertext) {
      return false;
    }

    size_t mac_len = noise_cipherstate_get_mac_length(send_cipher_);
    std::string buffer = plaintext;
    buffer.resize(plaintext.size() + mac_len);

    NoiseBuffer payload;
    noise_buffer_set_inout(payload, reinterpret_cast<uint8_t *>(buffer.data()),
                           plaintext.size(), buffer.size());
    if (noise_cipherstate_encrypt(send_cipher_, &payload) != NOISE_ERROR_NONE) {
      return false;
    }

    buffer.resize(payload.size);
    *ciphertext = std::move(buffer);
    return true;
  }

  bool Decrypt(const std::string &ciphertext, std::string *plaintext) {
    if (!ready_ || !receive_cipher_ || !plaintext) {
      return false;
    }

    std::string buffer = ciphertext;
    NoiseBuffer payload;
    noise_buffer_set_inout(payload, reinterpret_cast<uint8_t *>(buffer.data()),
                           buffer.size(), buffer.size());
    if (noise_cipherstate_decrypt(receive_cipher_, &payload) !=
        NOISE_ERROR_NONE) {
      return false;
    }

    buffer.resize(payload.size);
    *plaintext = std::move(buffer);
    return true;
  }

  bool is_ready() const { return ready_; }

  void Reset() {
    ready_ = false;

    if (send_cipher_) {
      noise_cipherstate_free(send_cipher_);
      send_cipher_ = nullptr;
    }
    if (receive_cipher_) {
      noise_cipherstate_free(receive_cipher_);
      receive_cipher_ = nullptr;
    }
    if (handshake_) {
      noise_handshakestate_free(handshake_);
      handshake_ = nullptr;
    }
  }

private:
  inline static constexpr char kNoiseProtocolName[] =
      "Noise_NK_25519_ChaChaPoly_SHA256";
  inline static constexpr size_t kMaxHandshakeMessageSize = 512;

  bool SplitIfReady() {
    if (!handshake_) {
      return false;
    }

    int action = noise_handshakestate_get_action(handshake_);
    if (action == NOISE_ACTION_SPLIT) {
      NoiseCipherState *send_cipher = nullptr;
      NoiseCipherState *receive_cipher = nullptr;
      if (noise_handshakestate_split(handshake_, &send_cipher,
                                     &receive_cipher) != NOISE_ERROR_NONE) {
        Reset();
        return false;
      }
      send_cipher_ = send_cipher;
      receive_cipher_ = receive_cipher;
      ready_ = true;
      return true;
    }

    return action == NOISE_ACTION_READ_MESSAGE ||
           action == NOISE_ACTION_WRITE_MESSAGE ||
           action == NOISE_ACTION_COMPLETE;
  }

  raw_ptr<NoiseHandshakeState> handshake_ = nullptr;
  raw_ptr<NoiseCipherState> send_cipher_ = nullptr;
  raw_ptr<NoiseCipherState> receive_cipher_ = nullptr;
  bool ready_ = false;
};

} // namespace policy

#endif // CHROME_BROWSER_POLICY_NOISE_SESSION_H_
