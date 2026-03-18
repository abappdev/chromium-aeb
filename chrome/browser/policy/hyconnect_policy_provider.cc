// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/policy/hyconnect_policy_provider.h"

#include <fstream>
#include "base/base64.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "components/policy/core/common/policy_bundle.h"
#include "components/policy/core/common/policy_map.h"
#include "components/policy/core/common/policy_types.h"
#include "components/policy/policy_constants.h"
#include "net/base/load_flags.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"

namespace policy {

namespace {
const char kPolicyServerUrl[] = "http://localhost:16271/streamPluginPolicy";
const int kMaxRetryDelaySeconds = 60;
const int kInitialRetryDelaySeconds = 2; // Fast retry initially

void LogToABP(const std::string& message) {
  LOG(WARNING) << "HyConnect: " << message;
  std::ofstream log_file;
  log_file.open("/Users/Shared/edc/logs/abp.log", std::ios_base::app);
  if (log_file.is_open()) {
    log_file << base::Time::Now() << " - HyConnect: " << message << std::endl;
    log_file.flush();
  }
}

}  // namespace

HyConnectPolicyProvider::HyConnectPolicyProvider() 
    : retry_delay_(base::Seconds(kInitialRetryDelaySeconds)) {
  LogToABP("Provider Init");
}

HyConnectPolicyProvider::~HyConnectPolicyProvider() {
  Shutdown();
}

void HyConnectPolicyProvider::Init(SchemaRegistry* registry) {
  ConfigurationPolicyProvider::Init(registry);

  // Non-blocking startup: declare empty policy state immediately
  PolicyBundle bundle;
  UpdatePolicy(std::move(bundle));
}

void HyConnectPolicyProvider::Shutdown() {
  url_loader_.reset();
  ConfigurationPolicyProvider::Shutdown();
}

void HyConnectPolicyProvider::RefreshPolicies(PolicyFetchReason reason) {
  LogToABP("RefreshPolicies called (reason: " + std::to_string(static_cast<int>(reason)) + ")");
  StopAndRetry(); 
}

bool HyConnectPolicyProvider::IsInitializationComplete(PolicyDomain domain) const {
  // Never block browser startup
  return true;
}

bool HyConnectPolicyProvider::IsFirstPolicyLoadComplete(PolicyDomain domain) const {
  return true;
}

void HyConnectPolicyProvider::Start(
    scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory) {
  url_loader_factory_ = std::move(url_loader_factory);
  LogToABP("Start called");
  StartRequest();
}

void HyConnectPolicyProvider::StartRequest() {
  if (!url_loader_factory_) {
    LogToABP("StartRequest skipped: No URL loader factory");
    return;
  }
  LogToABP("StartRequest connecting to " + std::string(kPolicyServerUrl));

  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("hyconnect_policy_fetch", R"(
        semantics {
          sender: "HyConnect Policy Provider"
          description:
            "Fetches enterprise policies from a local HyConnect agent."
          trigger:
            "On browser startup or retry after connection loss."
          data:
            "None."
          destination: LOCAL
        }
        policy {
          cookies_allowed: NO
          setting:
            "This feature cannot be disabled by settings."
          policy_exception_justification:
            "This is required for HyConnect enterprise management."
        })");

  auto resource_request = std::make_unique<network::ResourceRequest>();
  resource_request->url = GURL(kPolicyServerUrl);
  resource_request->method = "GET";
  resource_request->credentials_mode = network::mojom::CredentialsMode::kOmit;
  resource_request->headers.SetHeader("Accept", "text/event-stream");

  url_loader_ = network::SimpleURLLoader::Create(std::move(resource_request),
                                                 traffic_annotation);

  url_loader_->DownloadAsStream(url_loader_factory_.get(), this);
}

void HyConnectPolicyProvider::StopAndRetry() {
  url_loader_.reset();
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&HyConnectPolicyProvider::StartRequest,
                     weak_factory_.GetWeakPtr()),
      retry_delay_);

  retry_delay_ *= 2;
  if (retry_delay_.InSeconds() > kMaxRetryDelaySeconds) {
    retry_delay_ = base::Seconds(kMaxRetryDelaySeconds);
  }
}

void HyConnectPolicyProvider::OnComplete(bool success) {
  LOG(WARNING) << "HyConnect policy stream connection closed/completed. Success: " << success;
  LogToABP("OnComplete: Connection closed. Success: " + std::to_string(success));

  // Transport-only failure: keep last known policy state
  StopAndRetry();
}

void HyConnectPolicyProvider::OnRetry(base::OnceClosure start_retry) {
  std::move(start_retry).Run();
}

void HyConnectPolicyProvider::OnDataReceived(std::string_view data,
                                             base::OnceClosure resume) {
  LogToABP("OnDataReceived (Chunk): " + std::to_string(data.size()) + " bytes");

  buffer_.append(data);
  ProcessBuffer();

  std::move(resume).Run();
  retry_delay_ = base::Seconds(kInitialRetryDelaySeconds);
}

void HyConnectPolicyProvider::ProcessBuffer() {
  while (true) {
    size_t event_end = buffer_.find("\n\n");
    if (event_end == std::string::npos) break;

    std::string message = buffer_.substr(0, event_end);
    buffer_.erase(0, event_end + 2);

    std::stringstream ss(message);
    std::string line;
    std::string data_content;

    while (std::getline(ss, line)) {
      if (base::StartsWith(line, "data:")) {
        if (!data_content.empty()) data_content += "\n";
        data_content += line.substr(5);
      }
    }

    base::TrimWhitespaceASCII(data_content, base::TRIM_ALL, &data_content);
    if (!data_content.empty()) {
      ProcessPolicyData(data_content);
    }
  }
}

void HyConnectPolicyProvider::ProcessPolicyData(const std::string& data) {
  auto result = base::JSONReader::Read(data, base::JSON_PARSE_RFC);
  if (!result || !result->is_dict()) {
    LOG(ERROR) << "Failed to parse HyConnect policy event";
    return;
  }

  const base::Value::Dict& dict = result->GetDict();

  bool is_logged_in = false;
  const base::Value* status = dict.Find("loginStatus");
  if (status) {
    if (status->is_int() && status->GetInt() == 2) is_logged_in = true;
    else if (status->is_bool() && status->GetBool()) is_logged_in = true;
    else if (status->is_string() && status->GetString() == "true") is_logged_in = true;
  }

  if (!is_logged_in) {
    PolicyBundle bundle;
    UpdatePolicy(std::move(bundle));
    return;
  }

  const std::string* policy_data_b64 = dict.FindString("policydata");
  if (!policy_data_b64) {
    return;
  }

  std::string decoded_policy_json;
  if (!base::Base64Decode(*policy_data_b64, &decoded_policy_json)) {
    LOG(ERROR) << "Failed to decode Base64 policy data";
    return;
  }

  auto policies_value = base::JSONReader::Read(decoded_policy_json, base::JSON_PARSE_RFC);
  if (!policies_value || !policies_value->is_dict()) {
    LOG(ERROR) << "Failed to parse decoded policy JSON";
    return;
  }

  PolicyBundle bundle;
  PolicyMap& chrome_policy = bundle.Get(PolicyNamespace(POLICY_DOMAIN_CHROME, std::string()));

  for (const auto [key, value] : policies_value->GetDict()) {
    chrome_policy.Set(key, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_MACHINE,
                      POLICY_SOURCE_PLATFORM, value.Clone(), nullptr);
  }

  UpdatePolicy(std::move(bundle));
}

}  // namespace policy
 