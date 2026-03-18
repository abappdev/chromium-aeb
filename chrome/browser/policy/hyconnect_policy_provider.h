// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_
#define CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_

#include <memory>
#include <string>
#include <string_view>

#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "base/values.h"
#include "components/policy/core/common/configuration_policy_provider.h"
#include "services/network/public/cpp/simple_url_loader_stream_consumer.h"

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

namespace policy {

// A policy provider that reads policies from a local SSE stream
// (http://localhost:16271/streamPluginPolicy).
class HyConnectPolicyProvider : public ConfigurationPolicyProvider,
                                public network::SimpleURLLoaderStreamConsumer {
 public:
  HyConnectPolicyProvider();
  HyConnectPolicyProvider(const HyConnectPolicyProvider&) = delete;
  HyConnectPolicyProvider& operator=(const HyConnectPolicyProvider&) = delete;
  ~HyConnectPolicyProvider() override;

  // ConfigurationPolicyProvider implementation.
  void Init(SchemaRegistry* registry) override;
  void Shutdown() override;
  void RefreshPolicies(PolicyFetchReason reason) override;
  bool IsInitializationComplete(PolicyDomain domain) const override;
  bool IsFirstPolicyLoadComplete(PolicyDomain domain) const override;

  // Starts the connection to the policy server.
  void Start(scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory);

  // Stops the connection and retries later.
  void StopAndRetry();

  // Removes all policies provided by this provider.
  void RemovePolicies();

  // network::SimpleURLLoaderStreamConsumer implementation.
  void OnDataReceived(std::string_view data, base::OnceClosure resume) override;
  void OnComplete(bool success) override;
  void OnRetry(base::OnceClosure start_retry) override;

  // Tracks if the first policy fetch (or failure fallback) has completed.
  bool initial_fetch_complete_ = false;

  // Stores the set of policies currently applied, for audit and clean removal.
  base::Value::Dict last_applied_policies_;

 private:
  void StartRequest();
  void ProcessPolicyData(const std::string& data);
  void ProcessBuffer();
  bool DecryptPolicyData(const std::string& encrypted_base64,
                         std::string* decrypted_base64);

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
  std::unique_ptr<network::SimpleURLLoader> url_loader_;

  // Buffer for incoming SSE data.
  std::string buffer_;

  // Backoff delay for retries.
  base::TimeDelta retry_delay_;

  base::WeakPtrFactory<HyConnectPolicyProvider> weak_factory_{this};
};

}  // namespace policy

#endif  // CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_
