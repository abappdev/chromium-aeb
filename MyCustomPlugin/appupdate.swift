import Cocoa
import SwiftUI
import Foundation

// ===================== CONFIG =====================

let DEFAULT_SERVER = "https://public.server.com"
let SUPPORTED_COMPONENTS: Set<String> = [
    "hyworks-core",
    "workspace",
    "plugin",
    "xquartz"
]

// ===================== ADMIN ELEVATION =====================

func isRoot() -> Bool {
    return getuid() == 0
}

func relaunchAsAdmin() {
    let processInfo = ProcessInfo.processInfo
    let args = processInfo.arguments
    guard let firstArg = args.first else { exit(1) }
    
    // Convert to absolute path so `do shell script` finds it correctly from `/`
    var absolutePath = firstArg
    if !absolutePath.hasPrefix("/") {
        let cwd = FileManager.default.currentDirectoryPath
        if absolutePath.hasPrefix("./") {
            absolutePath = cwd + "/" + absolutePath.dropFirst(2)
        } else {
            absolutePath = cwd + "/" + absolutePath
        }
    }
    
    let script = """
    do shell script "quoted form of \\"\(absolutePath)\\"" with administrator privileges
    """
    
    var error: NSDictionary? = nil
    if let appleScript = NSAppleScript(source: script) {
        appleScript.executeAndReturnError(&error)
    }
    // Relaunched as root, exit this instance
    exit(0)
}

// ===================== MODELS =====================

struct Root: Codable {
    let mac: MacSection
}

struct MacSection: Codable {
    let components: [Component]
}

struct Component: Codable, Identifiable {
    var id: String { componentId }
    
    let componentId: String
    let type: String
    let file: String
    let version: String
    let md5: String
    let policy: String
    let runpre: Bool
    let runpost: Bool
    let app_name: String?
    
    enum CodingKeys: String, CodingKey {
        case componentId = "id"
        case type, file, version, md5, policy, runpre, runpost, app_name
    }
}

// ===================== SCRIPT ENGINE =====================

class ScriptRunner {
    static func runPre(id: String) throws {
        switch id {
        case "hyworks-core":
            print("Preinstall for hyworks-core: Stopping services...")
        case "workspace":
            print("Preinstall for workspace: Preparing workspace...")
        case "plugin":
            print("Preinstall for plugin")
        case "xquartz":
            print("Preinstall for xquartz")
        default:
            print("Default preinstall for \(id)")
        }
    }

    static func runPost(id: String) {
        switch id {
        case "hyworks-core":
            print("Postinstall for hyworks-core: Starting services...")
        case "workspace":
            print("Postinstall for workspace")
        case "plugin":
            print("Postinstall for plugin")
        case "xquartz":
            print("Postinstall for xquartz")
        default:
            print("Default postinstall for \(id)")
        }
    }
}

// ===================== VIEW MODEL =====================

@MainActor
class InstallerViewModel: ObservableObject {
    @Published var serverURL: String = DEFAULT_SERVER
    @Published var useCustomServer: Bool = false {
        didSet {
            if !useCustomServer { serverURL = DEFAULT_SERVER }
        }
    }
    
    @Published var components: [Component] = []
    @Published var selectedComponents: Set<String> = []
    
    @Published var fetchError: String? = nil
    @Published var isFetching: Bool = false
    
    @Published var isInstalling: Bool = false
    @Published var installProgress: Double = 0.0
    @Published var logs: String = ""
    @Published var installComplete: Bool = false
    @Published var installSuccess: Bool = false
    
    func log(_ message: String) {
        logs += "\(message)\n"
        print(message)
    }
    
    func fetchComponents() {
        fetchError = nil
        isFetching = true
        components = []
        selectedComponents = []
        
        guard let url = URL(string: serverURL + "/appupdates.json") else {
            fetchError = "Invalid Server URL"
            isFetching = false
            return
        }
        
        URLSession.shared.dataTask(with: url) { data, response, error in
            DispatchQueue.main.async {
                self.isFetching = false
                
                if let error = error {
                    self.fetchError = "Network error: \(error.localizedDescription)"
                    return
                }
                
                guard let data = data else {
                    self.fetchError = "No data received"
                    return
                }
                
                do {
                    let decoded = try JSONDecoder().decode(Root.self, from: data)
                    let rawComponents = decoded.mac.components
                    
                    var validComponents: [Component] = []
                    
                    for c in rawComponents {
                        // Strict validation layer
                        guard c.type == "pkg" || c.type == "zip" else {
                            self.fetchError = "Invalid JSON -> STOP INSTALLER: Unsupported type '\(c.type)' for '\(c.id)'"
                            return
                        }
                        
                        guard ["force", "optional", "ignore"].contains(c.policy) else {
                            self.fetchError = "Invalid JSON -> STOP INSTALLER: Invalid policy '\(c.policy)' for '\(c.id)'"
                            return
                        }
                        
                        if c.type == "zip" && (c.app_name == nil || c.app_name!.isEmpty) {
                            self.fetchError = "Invalid JSON -> STOP INSTALLER: ZIP component '\(c.id)' missing 'app_name'"
                            return
                        }
                        
                        // Enforce Allowlist (ignore unknown)
                        if !SUPPORTED_COMPONENTS.contains(c.id) {
                            continue
                        }
                        
                        validComponents.append(c)
                    }
                    
                    self.components = validComponents
                    
                    // Pre-select force constraint items
                    for c in validComponents {
                        if c.policy == "force" || c.policy == "optional" {
                            self.selectedComponents.insert(c.id)
                        }
                    }
                    
                } catch {
                    self.fetchError = "Invalid JSON -> STOP INSTALLER: Decoding failed -> \(error.localizedDescription)"
                }
            }
        }.resume()
    }
    
    func toggleSelection(for id: String) {
        if selectedComponents.contains(id) {
            selectedComponents.remove(id)
        } else {
            selectedComponents.insert(id)
        }
    }
    
    func startInstall() {
        guard !isInstalling else { return }
        isInstalling = true
        installProgress = 0.0
        logs = ""
        installComplete = false
        installSuccess = false
        
        let toInstall = components.filter { c in
            if c.policy == "ignore" { return false }
            if c.policy == "optional" && !selectedComponents.contains(c.id) { return false }
            return true
        }
        
        if toInstall.isEmpty {
            self.log("No components to install.")
            self.installSuccess = true
            self.installComplete = true
            self.isInstalling = false
            return
        }
        
        Task {
            var success = true
            for (index, component) in toInstall.enumerated() {
                await MainActor.run {
                    self.log("Starting installation for \(component.id)...")
                    self.installProgress = Double(index) / Double(toInstall.count)
                }
                
                let result = await self.installComponent(component)
                if !result {
                    success = false
                    await MainActor.run {
                        self.log("Failed to install \(component.id). Aborting further installations.")
                    }
                    break
                }
                
                await MainActor.run {
                    self.log("Successfully installed \(component.id).\n")
                }
            }
            
            await MainActor.run {
                self.installProgress = 1.0
                self.installSuccess = success
                self.installComplete = true
                self.isInstalling = false
                if success {
                    self.log("All selected components installed successfully.")
                }
            }
        }
    }
    
    private func installComponent(_ component: Component) async -> Bool {
        let localPath = "/tmp/\(component.file)"
        
        // 1. Download
        await MainActor.run { self.log("Downloading \(component.file)...") }
        let downloadSuccess = await download(component.file, to: localPath)
        if !downloadSuccess {
            await MainActor.run { self.log("Download failed.") }
            return false
        }
        
        // 2. Verify MD5
        await MainActor.run { self.log("Verifying MD5...") }
        if !verifyMD5(file: localPath, expected: component.md5) {
            await MainActor.run { self.log("MD5 mismatch for \(component.id). Expected \(component.md5)") }
            return false
        }
        
        // 3. Preinstall
        if component.runpre {
            await MainActor.run { self.log("Running preinstall...") }
            do {
                try ScriptRunner.runPre(id: component.id)
            } catch {
                await MainActor.run { self.log("Preinstall failed for \(component.id)") }
                return false
            }
        }
        
        // 4. Install
        var installSuccess = false
        if component.type == "pkg" {
            await MainActor.run { self.log("Installing PKG...") }
            installSuccess = installPKG(localPath)
        } else if component.type == "zip" {
            await MainActor.run { self.log("Installing ZIP...") }
            installSuccess = installZIP(component: component, path: localPath)
        }
        
        if !installSuccess {
            await MainActor.run { self.log("Installation step failed for \(component.id)") }
            return false
        }
        
        // 5. Postinstall
        if component.runpost {
            await MainActor.run { self.log("Running postinstall...") }
            ScriptRunner.runPost(id: component.id)
        }
        
        return true
    }
    
    private func download(_ file: String, to path: String) async -> Bool {
        let urlString = serverURL + "/" + file
        
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        task.arguments = ["-s", "-L", urlString, "-o", path]
        
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    private func verifyMD5(file: String, expected: String) -> Bool {
        let process = Process()
        let pipe = Pipe()
        
        process.standardOutput = pipe
        process.executableURL = URL(fileURLWithPath: "/sbin/md5")
        process.arguments = ["-q", file]
        
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let hash = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
            return hash == expected && process.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    private func installPKG(_ path: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/installer")
        process.arguments = ["-pkg", path, "-target", "/"]
        
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
    
    private func installZIP(component: Component, path: String) -> Bool {
        let tempDir = "/tmp/\(component.id)"
        
        if FileManager.default.fileExists(atPath: tempDir) {
            try? FileManager.default.removeItem(atPath: tempDir)
        }
        
        do {
            try FileManager.default.createDirectory(atPath: tempDir, withIntermediateDirectories: true)
        } catch {
            return false
        }
        
        let unzipProcess = Process()
        unzipProcess.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        unzipProcess.arguments = ["-q", path, "-d", tempDir]
        do {
            try unzipProcess.run()
            unzipProcess.waitUntilExit()
            if unzipProcess.terminationStatus != 0 { return false }
        } catch {
            return false
        }
        
        guard let appName = component.app_name else { return false }
        
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: tempDir) else { return false }
        let appBundles = contents.filter { $0.hasSuffix(".app") }
        
        if appBundles.count != 1 {
            DispatchQueue.main.async { self.log("ZIP Validation Failed: Found \(appBundles.count) app bundles. Expected exactly 1.") }
            return false
        }
        
        if appBundles.first! != appName {
            DispatchQueue.main.async { self.log("ZIP Validation Failed: Found \(appBundles.first!), expected \(appName)") }
            return false
        }
        
        let sourceAppPath = tempDir + "/" + appName
        let targetAppPath = "/Applications/" + appName
        
        if FileManager.default.fileExists(atPath: targetAppPath) {
            try? FileManager.default.removeItem(atPath: targetAppPath)
        }
        
        let cpProcess = Process()
        cpProcess.executableURL = URL(fileURLWithPath: "/bin/cp")
        cpProcess.arguments = ["-R", sourceAppPath, targetAppPath]
        
        do {
            try cpProcess.run()
            cpProcess.waitUntilExit()
            return cpProcess.terminationStatus == 0
        } catch {
            return false
        }
    }
}

// ===================== VIEWS =====================

struct ContentView: View {
    @StateObject private var vm = InstallerViewModel()
    
    var body: some View {
        VStack(spacing: 20) {
            Text("macOS Online Installer")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            if vm.isInstalling || vm.installComplete {
                installProgressView
            } else {
                setupView
            }
        }
        .padding(30)
        .frame(width: 600, height: 500)
    }
    
    var setupView: some View {
        VStack(alignment: .leading, spacing: 15) {
            GroupBox("Server Configuration") {
                VStack(alignment: .leading) {
                    Toggle("Use Custom Server", isOn: $vm.useCustomServer)
                    if vm.useCustomServer {
                        TextField("Server URL", text: $vm.serverURL)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    } else {
                        Text("Using public server: \(DEFAULT_SERVER)")
                            .foregroundColor(.secondary)
                    }
                }
                .padding(10)
            }
            
            Button("Fetch Updates") {
                vm.fetchComponents()
            }
            .disabled(vm.isFetching)
            
            if vm.isFetching {
                ProgressView("Fetching JSON...")
            }
            
            if let err = vm.fetchError {
                Text(err)
                    .foregroundColor(.white)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red)
                    .cornerRadius(8)
            }
            
            if !vm.components.isEmpty {
                GroupBox("Components") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(vm.components) { c in
                                if c.policy != "ignore" {
                                    HStack {
                                        let isForce = (c.policy == "force")
                                        let isSelected = vm.selectedComponents.contains(c.id)
                                        
                                        Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                                            .foregroundColor(isForce ? .secondary : .accentColor)
                                            .onTapGesture {
                                                if !isForce {
                                                    vm.toggleSelection(for: c.id)
                                                }
                                            }
                                        
                                        VStack(alignment: .leading) {
                                            Text(c.id).font(.headline)
                                            Text("v\(c.version) - \(c.type.uppercased())")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                        Spacer()
                                        if isForce {
                                            Text("Required")
                                                .font(.caption)
                                                .padding(.horizontal, 6)
                                                .padding(.vertical, 2)
                                                .background(Color.gray.opacity(0.3))
                                                .cornerRadius(4)
                                        }
                                    }
                                    .padding(.vertical, 4)
                                }
                            }
                        }
                        .padding(10)
                    }
                    .frame(maxHeight: 200)
                }
                
                HStack {
                    Spacer()
                    Button("Start Installation") {
                        vm.startInstall()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                }
            }
            
            Spacer()
        }
    }
    
    var installProgressView: some View {
        VStack(spacing: 20) {
            if vm.installComplete {
                VStack(spacing: 10) {
                    Image(systemName: vm.installSuccess ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .resizable()
                        .frame(width: 60, height: 60)
                        .foregroundColor(vm.installSuccess ? .green : .red)
                    Text(vm.installSuccess ? "Installation Complete" : "Installation Failed")
                        .font(.title2)
                        .fontWeight(.semibold)
                }
            } else {
                Text("Installing Components...")
                    .font(.title2)
                ProgressView(value: vm.installProgress)
            }
            
            ScrollView {
                Text(vm.logs)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(Color(NSColor.textBackgroundColor))
            .cornerRadius(8)
            
            if vm.installComplete {
                Button("Quit Installer") {
                    NSApplication.shared.terminate(nil)
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }
}

// ===================== APP ENTRY =====================

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        let contentView = ContentView()
        
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 600, height: 500),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false)
            
        window.center()
        window.title = "macOS Online Installer"
        window.contentView = NSHostingView(rootView: contentView)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

if !isRoot() {
    relaunchAsAdmin()
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()