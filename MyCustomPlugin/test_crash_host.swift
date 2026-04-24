import Cocoa
import SwiftUI

struct MyView: View { var body: some View { Text("Hello") } }

func isRoot() -> Bool { return getuid() == 0 }

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = NSHostingView(rootView: MyView())
        window.title = "Test"
        window.makeKeyAndOrderFront(nil)
    }
}
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
