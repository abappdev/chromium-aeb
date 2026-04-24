// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_
#define CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "base/base_paths.h"
#include "base/environment.h"
#include "base/files/file_path.h"
#include "base/memory/weak_ptr.h"
#include "base/path_service.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "chrome/browser/policy/noise_session.h"
#include "components/policy/core/common/configuration_policy_provider.h"
#include "services/network/public/cpp/simple_url_loader_stream_consumer.h"

class GURL;

namespace network::mojom {
class URLResponseHead;
}

namespace network {
class SharedURLLoaderFactory;
class SimpleURLLoader;
}  // namespace network

namespace policy {

// Common paths used by the HyConnect integration.
inline base::FilePath GetEdcPath() {
#if BUILDFLAG(IS_MAC)
  return base::FilePath("/Users/Shared/edc");
#elif BUILDFLAG(IS_WIN)
  base::FilePath local_app_data;
  if (base::PathService::Get(base::DIR_LOCAL_APP_DATA, &local_app_data)) {
    return local_app_data.AppendASCII("Accops")
        .AppendASCII("edc")
        .AppendASCII("softclient");
  }
  return base::FilePath(L"C:/Users/Default/AppData/Local/Accops/edc/softclient");
#else
  std::unique_ptr<base::Environment> env = base::Environment::Create();
  if (env) {
    std::optional<std::string> home = env->GetVar(base::env_vars::kHome);
    if (home && !home->empty()) {
      return base::FilePath(*home).AppendASCII(".edc");
    }
  }
  return base::FilePath("/home/default/.edc");
#endif
}

inline base::FilePath GetAbpLogFilePath() {
  return GetEdcPath().AppendASCII("logs").AppendASCII("accops_sphere.log");
}

inline base::FilePath GetSpherePublicKeyPath() {
  return GetEdcPath().AppendASCII("sphere.pub");
}

// A policy provider that reads policies from a local SSE stream
// (http://localhost:16272/streamPluginPolicy).
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
  void ProcessDecryptedPolicyData(const std::string& data);
  void ProcessBuffer();
  void OnResponseStarted(const GURL& final_url,
                         const network::mojom::URLResponseHead& response_head);
  void OnPublicKeyRead(std::optional<std::array<uint8_t, 32>> public_key);

  scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory_;
  std::unique_ptr<network::SimpleURLLoader> url_loader_;

  // Buffer for incoming SSE data.
  std::string buffer_;

  // Backoff delay for retries.
  base::TimeDelta retry_delay_;

  NoiseSession noise_session_;
  bool noise_ready_ = false;

  base::WeakPtrFactory<HyConnectPolicyProvider> weak_factory_{this};
};

}  // namespace policy

#endif  // CHROME_BROWSER_POLICY_HYCONNECT_POLICY_PROVIDER_H_
