// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/policy/hyconnect_policy_provider.h"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <sstream>
#include <vector>

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread_restrictions.h"
#include "components/policy/core/common/policy_bundle.h"
#include "components/policy/core/common/policy_map.h"
#include "components/policy/core/common/policy_types.h"
#include "components/policy/policy_constants.h"
#include "net/base/load_flags.h"
#include "net/http/http_response_headers.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "services/network/public/cpp/simple_url_loader.h"
#include "services/network/public/mojom/url_response_head.mojom.h"

namespace policy {
namespace {
static std::atomic<bool> g_accops_app_exists{false};
static std::atomic<bool> g_accops_app_checked{false};

void CheckAccopsAppExistsBackground() {
  g_accops_app_exists = base::PathExists(base::FilePath(kAccopsWorkspaceAppPath));
  g_accops_app_checked = true;
}

void LogToABP(const std::string& message) {
  if (!g_accops_app_checked) {
    static bool check_posted = false;
    if (!check_posted) {
      check_posted = true;
      base::ThreadPool::PostTask(FROM_HERE, {base::MayBlock(), base::TaskPriority::BEST_EFFORT}, base::BindOnce(&CheckAccopsAppExistsBackground));
    }
    return;
  }
  if (!g_accops_app_exists) {
    return;
  }
  LOG(WARNING) << "HyConnect Provider: " << message;
  std::ofstream log_file;
  log_file.open(kHyConnectLogFilePath, std::ios_base::app);
  if (log_file.is_open()) {
    log_file << base::Time::Now() << " - HyConnect: " << message << std::endl;
    log_file.flush();
  }
}

const char kPolicyServerUrl[] = "http://localhost:16271/streamPluginPolicy";
const char kNoiseHandshakeHeader[] = "X-Noise-Handshake";
const int kInitialRetryDelaySeconds = 1;
const char kPinnedServerStaticPublicKeyHex[] =
    "551f4f11d6ea7085f4d3258f46f77982bf170f60469c932c507dda3ae9f96f4d";

std::array<uint8_t, 32> GetPinnedServerStaticPublicKey() {
  std::array<uint8_t, 32> key = {};
  std::vector<uint8_t> decoded;
  bool ok = base::HexStringToBytes(kPinnedServerStaticPublicKeyHex, &decoded);
  CHECK(ok);
  CHECK_EQ(decoded.size(), key.size());
  std::copy(decoded.begin(), decoded.end(), key.begin());
  return key;
}

// TruncateForLog removed for security / preventing sensitive data in logs
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
  noise_session_.Reset();
  noise_ready_ = false;
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

  noise_session_.Reset();
  noise_ready_ = false;
  buffer_.clear();

  std::string client_handshake;
  if (!noise_session_.InitializeInitiator(GetPinnedServerStaticPublicKey()) ||
      !noise_session_.WriteHandshakeMessage(&client_handshake)) {
    LogToABP("StartRequest failed: initiator handshake generation failed");
    StopAndRetry();
    return;
  }

  std::string client_handshake_b64 = base::Base64Encode(client_handshake);
  LogToABP("StartRequest connecting to " + std::string(kPolicyServerUrl) +
           ", client_handshake_bytes=" +
           std::to_string(client_handshake.size()));

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
  resource_request->headers.SetHeader(kNoiseHandshakeHeader,
                                      client_handshake_b64);

  url_loader_ = network::SimpleURLLoader::Create(std::move(resource_request),
                                                 traffic_annotation);
  url_loader_->SetOnResponseStartedCallback(base::BindOnce(
      &HyConnectPolicyProvider::OnResponseStarted, weak_factory_.GetWeakPtr()));

  url_loader_->DownloadAsStream(url_loader_factory_.get(), this);
}

void HyConnectPolicyProvider::StopAndRetry() {
  LogToABP("StopAndRetry scheduled in " + std::to_string(retry_delay_.InSeconds()) +
           "s");
  noise_session_.Reset();
  noise_ready_ = false;
  buffer_.clear();
  url_loader_.reset();
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&HyConnectPolicyProvider::StartRequest,
                     weak_factory_.GetWeakPtr()),
      retry_delay_);
  retry_delay_ = base::Seconds(kInitialRetryDelaySeconds);
}

void HyConnectPolicyProvider::OnComplete(bool success) {
  LOG(WARNING) << "HyConnect policy stream connection closed/completed. Success: " << success;
  LogToABP("OnComplete: Connection closed. Success: " + std::to_string(success));

  // Transport-only failure: keep last known policy state
  StopAndRetry();
}

void HyConnectPolicyProvider::OnRetry(base::OnceClosure start_retry) {
  LogToABP("OnRetry called by SimpleURLLoader");
  std::move(start_retry).Run();
}

void HyConnectPolicyProvider::OnResponseStarted(
    const GURL& final_url,
    const network::mojom::URLResponseHead& response_head) {
  if (!response_head.headers) {
    LogToABP("OnResponseStarted failed: missing HTTP headers");
    StopAndRetry();
    return;
  }

  LogToABP("OnResponseStarted: url=" + final_url.spec() +
           ", response_code=" +
           std::to_string(response_head.headers->response_code()));
  std::optional<std::string> server_handshake_b64 =
      response_head.headers->GetNormalizedHeader(kNoiseHandshakeHeader);
  if (!server_handshake_b64) {
    LogToABP("OnResponseStarted failed: missing X-Noise-Handshake header");
    StopAndRetry();
    return;
  }

  std::string server_handshake;
  std::string server_handshake_b64_str =
      base::CollapseWhitespaceASCII(*server_handshake_b64, true);
  if (!base::Base64Decode(server_handshake_b64_str, &server_handshake)) {
    LogToABP("OnResponseStarted failed: server handshake base64 decode failed");
    StopAndRetry();
    return;
  }

  LogToABP("OnResponseStarted: server_handshake_bytes=" +
           std::to_string(server_handshake.size()));
  if (!noise_session_.ReadHandshakeMessage(server_handshake)) {
    LogToABP("OnResponseStarted failed: Noise handshake read failed");
    StopAndRetry();
    return;
  }

  if (!noise_session_.is_ready()) {
    LogToABP("OnResponseStarted failed: Noise session not ready after handshake");
    StopAndRetry();
    return;
  }

  noise_ready_ = true;
  retry_delay_ = base::Seconds(kInitialRetryDelaySeconds);
  LogToABP("Noise handshake completed successfully");
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
    size_t delimiter_length = 2;
    if (event_end == std::string::npos) {
      event_end = buffer_.find("\r\n\r\n");
      delimiter_length = 4;
    }
    if (event_end == std::string::npos) break;

    std::string message = buffer_.substr(0, event_end);
    buffer_.erase(0, event_end + delimiter_length);

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
      // Removed preview= to prevent sensitive data in logs
      LogToABP("ProcessBuffer extracted SSE data bytes=" +
               std::to_string(data_content.size()));
      ProcessPolicyData(data_content);
    }
  }
}

void HyConnectPolicyProvider::ProcessPolicyData(const std::string& data) {
  if (!noise_ready_) {
    LogToABP("ProcessPolicyData ignored: noise session not ready");
    return;
  }

  auto outer_result = base::JSONReader::Read(data, base::JSON_PARSE_RFC);
  if (!outer_result || !outer_result->is_dict()) {
    LogToABP("ProcessPolicyData failed: outer JSON parse failed");
    return;
  }

  const std::string* awc_data_b64 = outer_result->GetDict().FindString("awcData");
  if (!awc_data_b64) {
    LogToABP("ProcessPolicyData failed: outer JSON missing awcData");
    return;
  }

  std::string encrypted_payload;
  if (!base::Base64Decode(*awc_data_b64, &encrypted_payload)) {
    LogToABP("ProcessPolicyData failed: awcData base64 decode failed");
    return;
  }

  std::string decrypted_payload;
  if (!noise_session_.Decrypt(encrypted_payload, &decrypted_payload)) {
    LogToABP("ProcessPolicyData failed: Noise decrypt failed, ciphertext_bytes=" +
             std::to_string(encrypted_payload.size()));
    return;
  }

  LogToABP("ProcessPolicyData decrypt ok: plaintext_bytes=" +
           std::to_string(decrypted_payload.size()));
  ProcessDecryptedPolicyData(decrypted_payload);
  
  // Securely clear the sensitive plaintext from memory to prevent extraction from memory dumps
  std::fill(decrypted_payload.begin(), decrypted_payload.end(), '\0');
}

void HyConnectPolicyProvider::ProcessDecryptedPolicyData(
    const std::string& data) {
  auto result = base::JSONReader::Read(data, base::JSON_PARSE_RFC);
  if (!result || !result->is_dict()) {
    LogToABP("ProcessDecryptedPolicyData failed: inner JSON parse failed");
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
    LogToABP("ProcessDecryptedPolicyData: loginStatus=false, clearing policies");
    last_applied_policies_.clear();
    PolicyBundle bundle;
    UpdatePolicy(std::move(bundle));
    return;
  }

  const std::string* policy_data_b64 = dict.FindString("policydata");
  if (!policy_data_b64) {
    LogToABP("ProcessDecryptedPolicyData failed: missing policydata");
    return;
  }

  std::string decoded_policy_json;
  if (!base::Base64Decode(*policy_data_b64, &decoded_policy_json)) {
    LOG(ERROR) << "Failed to decode Base64 policy data";
    LogToABP("ProcessDecryptedPolicyData failed: policydata base64 decode failed");
    return;
  }

  auto policies_value = base::JSONReader::Read(decoded_policy_json, base::JSON_PARSE_RFC);
  if (!policies_value || !policies_value->is_dict()) {
    LOG(ERROR) << "Failed to parse decoded policy JSON";
    LogToABP("ProcessDecryptedPolicyData failed: decoded policy JSON parse failed");
    std::fill(decoded_policy_json.begin(), decoded_policy_json.end(), '\0');
    return;
  }

  if (policies_value->GetDict().empty()) {
    if (!last_applied_policies_.empty()) {
      LogToABP("ProcessDecryptedPolicyData: ignoring empty logged-in policy payload and preserving last HyConnect policies");
      return;
    }
    LogToABP("ProcessDecryptedPolicyData: logged-in policy payload is empty and no prior HyConnect policies exist");
  }

  PolicyBundle bundle;
  PolicyMap& chrome_policy = bundle.Get(PolicyNamespace(POLICY_DOMAIN_CHROME, std::string()));

  for (const auto [key, value] : policies_value->GetDict()) {
    chrome_policy.Set(key, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_MACHINE,
                      POLICY_SOURCE_PLATFORM, value.Clone(), nullptr);
  }

  LogToABP("Applying " + std::to_string(policies_value->GetDict().size()) +
           " policies.");
  last_applied_policies_ = policies_value->GetDict().Clone();
  UpdatePolicy(std::move(bundle));
  
  // Securely clear the decoded JSON from memory
  std::fill(decoded_policy_json.begin(), decoded_policy_json.end(), '\0');
}

}  // namespace policy
 
