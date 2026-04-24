// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/policy/hyconnect_policy_provider.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
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
static std::atomic<bool> g_abp_log_dir_exists{false};
static std::atomic<bool> g_abp_log_dir_checked{false};
constexpr size_t kMaxLogFileReadBytes = 4 * 1024 * 1024;
constexpr base::TimeDelta kLogRetention = base::Hours(48);

void CheckAbpLogDirExistsBackground() {
  g_abp_log_dir_exists = base::PathExists(GetAbpLogFilePath().DirName());
  g_abp_log_dir_checked = true;
}

std::string BuildRetainedLogContent(const std::string& existing_content,
                                    const std::string& new_entry,
                                    int64_t cutoff_ms) {
  std::stringstream input(existing_content);
  std::string line;
  std::string output;
  while (std::getline(input, line)) {
    if (line.empty()) {
      continue;
    }

    const size_t separator = line.find('|');
    if (separator == std::string::npos) {
      continue;
    }

    int64_t timestamp_ms = 0;
    if (!base::StringToInt64(line.substr(0, separator), &timestamp_ms) ||
        timestamp_ms < cutoff_ms) {
      continue;
    }

    output.append(line);
    output.push_back('\n');
  }

  output.append(new_entry);
  output.push_back('\n');
  return output;
}

void WriteHyConnectProviderLogEntryToFile(const std::string& new_entry,
                                          int64_t cutoff_ms) {
  const base::FilePath edc_path = GetEdcPath();
  if (!base::PathExists(edc_path)) {
    return;
  }

  const base::FilePath log_path = GetAbpLogFilePath();
  base::CreateDirectory(log_path.DirName());

  std::string existing_content;
  base::ReadFileToStringWithMaxSize(log_path, &existing_content,
                                    kMaxLogFileReadBytes);
  const std::string pruned_content =
      BuildRetainedLogContent(existing_content, new_entry, cutoff_ms);
  base::WriteFile(log_path, pruned_content);
}

void LogToABP(const std::string& message) {
  if (!g_abp_log_dir_checked) {
    static bool check_posted = false;
    if (!check_posted) {
      check_posted = true;
      base::ThreadPool::PostTask(FROM_HERE, {base::MayBlock(), base::TaskPriority::BEST_EFFORT}, base::BindOnce(&CheckAbpLogDirExistsBackground));
    }
    return;
  }
  if (!g_abp_log_dir_exists) {
    return;
  }
  LOG(WARNING) << "HyConnect Provider: " << message;

  const base::Time now = base::Time::Now();
  const int64_t now_ms = now.InMillisecondsSinceUnixEpoch();
  const int64_t cutoff_ms = (now - kLogRetention).InMillisecondsSinceUnixEpoch();
  const std::string new_entry =
      std::to_string(now_ms) + "|" + base::ToString(now) + " - HyConnect: " +
      message;

  base::ThreadPool::PostTask(
      FROM_HERE,
      {base::MayBlock(), base::TaskPriority::BEST_EFFORT},
      base::BindOnce(&WriteHyConnectProviderLogEntryToFile, new_entry,
                     cutoff_ms));
}

const char kPolicyServerUrl[] = "http://localhost:16271/streamPluginPolicy";
const char kNoiseHandshakeHeader[] = "X-Noise-Handshake";
const int kInitialRetryDelaySeconds = 1;

std::optional<std::array<uint8_t, 32>> ReadPublicKeyFile(const base::FilePath& path) {
  std::string file_content;
  if (!base::ReadFileToStringWithMaxSize(path, &file_content, 1024) || file_content.empty()) {
    return std::nullopt;
  }
  
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &file_content);
  
  std::vector<uint8_t> decoded;
  if (!base::HexStringToBytes(file_content, &decoded) || decoded.size() != 32) {
    return std::nullopt;
  }
  
  std::array<uint8_t, 32> key;
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

  base::FilePath key_path = GetSpherePublicKeyPath();

  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::BEST_EFFORT},
      base::BindOnce(&ReadPublicKeyFile, key_path),
      base::BindOnce(&HyConnectPolicyProvider::OnPublicKeyRead, weak_factory_.GetWeakPtr()));
}

void HyConnectPolicyProvider::OnPublicKeyRead(std::optional<std::array<uint8_t, 32>> public_key) {
  if (!public_key) {
    LogToABP("Connection initialization failed: key unavailable");
    StopAndRetry();
    return;
  }

  std::string client_handshake;
  if (!noise_session_.InitializeInitiator(public_key.value()) ||
      !noise_session_.WriteHandshakeMessage(&client_handshake)) {
    LogToABP("Connection initialization failed");
    StopAndRetry();
    return;
  }

  std::string client_handshake_b64 = base::Base64Encode(client_handshake);
  LogToABP("Connecting to local policy service");

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

  LogToABP("Service responded with code: " + std::to_string(response_head.headers->response_code()));
  std::optional<std::string> server_handshake_b64 =
      response_head.headers->GetNormalizedHeader(kNoiseHandshakeHeader);
  if (!server_handshake_b64) {
    LogToABP("Connection rejected: missing required headers");
    StopAndRetry();
    return;
  }

  std::string server_handshake;
  std::string server_handshake_b64_str =
      base::CollapseWhitespaceASCII(*server_handshake_b64, true);
  if (!base::Base64Decode(server_handshake_b64_str, &server_handshake)) {
    LogToABP("Connection rejected: invalid header format");
    StopAndRetry();
    return;
  }

  if (!noise_session_.ReadHandshakeMessage(server_handshake)) {
    LogToABP("Connection rejected: validation failed");
    StopAndRetry();
    return;
  }

  if (!noise_session_.is_ready()) {
    LogToABP("Connection rejected: session setup incomplete");
    StopAndRetry();
    return;
  }

  noise_ready_ = true;
  retry_delay_ = base::Seconds(kInitialRetryDelaySeconds);
  LogToABP("Secure connection established");
}

void HyConnectPolicyProvider::OnDataReceived(std::string_view data,
                                             base::OnceClosure resume) {
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
      ProcessPolicyData(data_content);
    }
  }
}

void HyConnectPolicyProvider::ProcessPolicyData(const std::string& data) {
  if (!noise_ready_) {
    LogToABP("Data ignored: secure session not ready");
    return;
  }

  auto outer_result = base::JSONReader::Read(data, base::JSON_PARSE_RFC);
  if (!outer_result || !outer_result->is_dict()) {
    LogToABP("Data processing failed: invalid payload format");
    return;
  }

  const std::string* awc_data_b64 = outer_result->GetDict().FindString("awcData");
  if (!awc_data_b64) {
    LogToABP("Data processing failed: invalid payload format");
    return;
  }

  std::string encrypted_payload;
  if (!base::Base64Decode(*awc_data_b64, &encrypted_payload)) {
    LogToABP("Data processing failed: invalid payload format");
    return;
  }

  std::string decrypted_payload;
  if (!noise_session_.Decrypt(encrypted_payload, &decrypted_payload)) {
    LogToABP("Data processing failed: structured payload validation error");
    return;
  }

  ProcessDecryptedPolicyData(decrypted_payload);
  
  // Securely clear the sensitive plaintext from memory to prevent extraction from memory dumps
  std::fill(decrypted_payload.begin(), decrypted_payload.end(), '\0');
}

void HyConnectPolicyProvider::ProcessDecryptedPolicyData(
    const std::string& data) {
  auto result = base::JSONReader::Read(data, base::JSON_PARSE_RFC);
  if (!result || !result->is_dict()) {
    LogToABP("Policy configuration parse failed");
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
    LogToABP("Local state indicates unavailable policies. Clearing applied rules.");
    last_applied_policies_.clear();
    PolicyBundle bundle;
    UpdatePolicy(std::move(bundle));
    return;
  }

  const std::string* policy_data_b64 = dict.FindString("policydata");
  if (!policy_data_b64) {
    LogToABP("Policy configuration missing required payload");
    return;
  }

  std::string decoded_policy_json;
  if (!base::Base64Decode(*policy_data_b64, &decoded_policy_json)) {
    LOG(ERROR) << "Failed to decode Base64 policy data";
    LogToABP("Policy decoding error");
    return;
  }

  auto policies_value = base::JSONReader::Read(decoded_policy_json, base::JSON_PARSE_RFC);
  if (!policies_value || !policies_value->is_dict()) {
    LOG(ERROR) << "Failed to parse decoded policy JSON";
    LogToABP("Policy payload processing error");
    std::fill(decoded_policy_json.begin(), decoded_policy_json.end(), '\0');
    return;
  }

  if (policies_value->GetDict().empty()) {
    if (!last_applied_policies_.empty()) {
      LogToABP("Preserving previous policies due to empty update");
      return;
    }
    LogToABP("No policies to apply currently");
  }

  PolicyBundle bundle;
  PolicyMap& chrome_policy = bundle.Get(PolicyNamespace(POLICY_DOMAIN_CHROME, std::string()));

  for (const auto [key, value] : policies_value->GetDict()) {
    chrome_policy.Set(key, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_MACHINE,
                      POLICY_SOURCE_PLATFORM, value.Clone(), nullptr);
  }

  LogToABP("Applying updated policies");
  last_applied_policies_ = policies_value->GetDict().Clone();
  UpdatePolicy(std::move(bundle));
  
  // Securely clear the decoded JSON from memory
  std::fill(decoded_policy_json.begin(), decoded_policy_json.end(), '\0');
}

}  // namespace policy
 
