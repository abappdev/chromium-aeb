# ----------------------------------------------------
# Common files for all platforms
# ----------------------------------------------------

# Common HEADERS
HEADERS += \
    ./client.h \
    ./HySecureAppDataParser.h \
    ./HysecureAppUtility.h \
    ./abstractions/baseui.h \
    ./abstractions/constants.h \
    ./abstractions/sessionlauncher.h \
    ./components/AccopsBrowserPolicyServer.h \
    ./components/NoiseSession.h \
    ./components/sessionhandler.h \
    ./components/sessionmanager.h \
    ./components/mainui.h \
    ./components/mainuihelper.h \
    ./components/settingsui.h \
    ./components/UpdateDetailsDialog.h \
    ./components/UIManager.h \
    ./components/appdesktopvieweruihandler.h \
    ./components/applicationmainuihandler.h \
    ./components/controlleruihandler.h \
    ./components/desktopmanager.h \
    ./components/qmltouchscreen.h \
    ./components/qmluiconstants.h \
    ./components/settingsuihandler.h \
    ./components/viewericonimageprovider.h \
    ./components/hysecuredatahandler.h \
    ./components/hysecurecommhandler.h \
    ./components/qmlAnnouncement.h \
    ./components/progateuihandler.h \
    ./components/ProgateViewerMonitor.h \
    $$PWD/../common/common.h \
    $$PWD/../common/ConfigStore.h \
    $$PWD/../common/CommonUIHandler.h \
    $$PWD/../common/edcRunGuard.h \
    $$PWD/../common/globals.h \
    $$PWD/../common/localclienthandler.h \
    $$PWD/../common/localclient.h \
    $$PWD/../common/localserver.h \
    $$PWD/../common/localserverclient.h \
    $$PWD/../common/localudpcommhandler.h \
    $$PWD/../common/Message.h \
    $$PWD/../common/PropertyBag.h \
    $$PWD/../common/PLog.h \
    $$PWD/../common/serializer.h \
    $$PWD/../common/versions.h \
    $$PWD/../common/simplecrypt.h \
    $$PWD/../common/qaesencryption.h \
    $$PWD/../common/xmldatahandler.h \
    $$PWD/../common/HySecureJsonDataParser.h 

# Common SOURCES
SOURCES += \
    ./client.cpp \
    ./main.cpp \
    ./HySecureAppDataParser.cpp \
    ./HysecureAppUtility.cpp \
    ./abstractions/sessionlauncher.cpp \
    ./components/sessionhandler.cpp \
    ./components/sessionmanager.cpp \
    ./components/mainui.cpp \
    ./components/mainuihelper.cpp \
    ./components/settingsui.cpp \
    ./components/UIManager.cpp \
    ./components/appdesktopvieweruihandler.cpp \
    ./components/applicationmainuihandler.cpp \
    ./components/controlleruihandler.cpp \
    ./components/desktopmanager.cpp \
    ./components/qmltouchscreen.cpp \
    ./components/settingsuihandler.cpp \
    ./components/viewericonimageprovider.cpp \
    ./components/hysecuredatahandler.cpp \
    ./components/hysecurecommhandler.cpp \
    ./components/qmlAnnouncement.cpp \
    ./components/progateuihandler.cpp \
    ./components/ProgateViewerMonitor.cpp \
    ./components/UpdateDetailsDialog.cpp \
    $$PWD/../common/common.cpp \
    $$PWD/../common/ConfigStore.cpp \
    $$PWD/../common/CommonUIHandler.cpp \
    $$PWD/../common/edcRunGuard.cpp \
    $$PWD/../common/localclienthandler.cpp \
    $$PWD/../common/localclient.cpp \
    $$PWD/../common/localserver.cpp \
    $$PWD/../common/localserverclient.cpp \
    $$PWD/../common/localudpcommhandler.cpp \
    $$PWD/../common/PLog.cpp \
    $$PWD/../common/serializer.cpp \
    $$PWD/../common/simplecrypt.cpp \
    $$PWD/../common/qaesencryption.cpp \
    $$PWD/../common/xmldatahandler.cpp \
    $$PWD/../common/HySecureJsonDataParser.cpp 

# Resources and Translations
RESOURCES += ./edcui.qrc

TRANSLATIONS += \
    translations/57e2b128-e5ab-4c81-9608-c31c6f950cbe.ts \
    translations/c60ef985-ba66-4c59-ab1f-78cc2d5238ba.ts

# QML Files for Translation
lupdate_only {
    SOURCES += \
        ./Resources/qml/*.qml \
        ./Resources/qml/2.4/*.qml
}

# ----------------------------------------------------
# Windows-specific configuration
# ----------------------------------------------------
win32 {
    message("Running on Windows")

    HEADERS += \
        ./components/LauncherMSTSC.h \
        $$PWD/components/launchmstscthread.h \
        $$PWD/components/rdppipenotifierthread.h \
        $$PWD/virtualChannelServer/tcpserverthread.h \
        $$PWD/virtualChannelServer/tcpserver.h \
        $$PWD/virtualChannelServer/clientinfo_request.h \
        $$PWD/virtualChannelServer/clientinfo_response.h \
        $$PWD/virtualChannelServer/vcrequestobject.h\
        $$PWD/../common/CrashDumpMgr.h

    SOURCES += \
        ./components/LauncherMSTSC.cpp \
        $$PWD/components/launchmstscthread.cpp \
        $$PWD/components/rdppipenotifierthread.cpp \
        $$PWD/virtualChannelServer/tcpserverthread.cpp \
        $$PWD/virtualChannelServer/tcpserver.cpp \
        $$PWD/virtualChannelServer/clientinfo_request.cpp \
        $$PWD/virtualChannelServer/clientinfo_response.cpp \
        $$PWD/virtualChannelServer/vcrequestobject.cpp \
        $$PWD/../common/CrashDumpMgr.cpp
}

# ----------------------------------------------------
# macOS-specific configuration
# ----------------------------------------------------
macx {
    message("Running on macOS")

    HEADERS += \
        ./components/LauncherMAC.h \
        ./components/rdplauncher.h \
        ./abstractions/tpcif.h

    SOURCES += \
        ./components/LauncherMAC.cpp \
        ./components/rdplauncher.cpp

    DISTFILES += \
        $$PWD/Resources/qml/CaptchaDialog.qml
}

# ----------------------------------------------------
# Linux-specific configuration
# ----------------------------------------------------
unix:!macx {
    message("Running on Linux")

    HEADERS += \
        ./components/rdplauncher.h \
        ./abstractions/tpcif.h

    SOURCES += \
        ./components/rdplauncher.cpp
}
