
#ifndef ACCOPSBROWSERPOLICYSERVER_H
#define ACCOPSBROWSERPOLICYSERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QStringList>
#include <QHostAddress>
#include <QList>
#include <QHash>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QTimer>
#include <QtGlobal>
#include <QByteArray>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include "PLog.h"
#include "CommonUIHandler.h"
#include "NoiseSession.h"

#include <random>
#include <QFile>
#include <QDir>
#include <QProcessEnvironment>
#include <noise/protocol.h>
#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <sys/mman.h>
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16 // Fallback
#endif
#endif

namespace
{
const char kNoiseHandshakeHeader[] = "X-Noise-Handshake";

QString publicKeyFilePath()
{
#ifdef Q_OS_MAC
    return QString::fromLatin1("/Users/Shared/edc/sphere.pub");
#elif defined(Q_OS_WIN)
    QString localAppData = QProcessEnvironment::systemEnvironment().value(
        QString::fromLatin1("LOCALAPPDATA"));
    if (localAppData.isEmpty())
        localAppData = QDir::homePath() + QString::fromLatin1("/AppData/Local");
    return QDir::fromNativeSeparators(localAppData) +
           QString::fromLatin1("/Accops/edc/softclient/sphere.pub");
#else
    return QDir::homePath() + QString::fromLatin1("/.edc/sphere.pub");
#endif
}

// truncateForLog removed for security / preventing sensitive data in logs

bool normalizePolicyForWire(const QString &policy,
                            QByteArray &policyDataB64,
                            QByteArray &normalizedPolicyJson,
                            QByteArray &parseMode)
{
    const QByteArray trimmed = policy.trimmed().toUtf8();
    if (trimmed.isEmpty())
    {
        normalizedPolicyJson = "{}";
        policyDataB64 = normalizedPolicyJson.toBase64();
        parseMode = "empty->json";
        return true;
    }

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(trimmed, &error);
    if (error.error == QJsonParseError::NoError && !doc.isNull())
    {
        normalizedPolicyJson = doc.toJson(QJsonDocument::Compact);
        policyDataB64 = normalizedPolicyJson.toBase64();
        parseMode = "raw-json";
        return true;
    }

    const QByteArray decoded = QByteArray::fromBase64(trimmed);
    QJsonParseError decodedError;
    QJsonDocument decodedDoc = QJsonDocument::fromJson(decoded, &decodedError);
    if (decodedError.error == QJsonParseError::NoError && !decodedDoc.isNull())
    {
        normalizedPolicyJson = decodedDoc.toJson(QJsonDocument::Compact);
        policyDataB64 = normalizedPolicyJson.toBase64();
        parseMode = "base64-json";
        return true;
    }

    normalizedPolicyJson = trimmed;
    policyDataB64 = normalizedPolicyJson.toBase64();
    parseMode = "raw-unknown";
    return false;
}

QString extractHeaderValue(const QStringList &lines, const QString &headerName)
{
    const QString prefix = headerName + ":";
    foreach (const QString &line, lines)
    {
        if (line.startsWith(prefix, Qt::CaseInsensitive))
            return line.mid(prefix.length()).trimmed();
    }

    return QString();
}
}

class AccopsBrowserPolicyServer : public QTcpServer
{
    Q_OBJECT

public:
    static AccopsBrowserPolicyServer *instance()
    {
        static AccopsBrowserPolicyServer *s_instance = 0;
        if (!s_instance)
            s_instance = new AccopsBrowserPolicyServer(0);
        return s_instance;
    }

    bool start(quint16 port)
    {
        if (m_running)
        {
            PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                                  "PolicyServer already running on port %d", port);
            return true;
        }

        // --- START DYNAMIC KEY GENERATION ---
        m_serverStaticPrivateKey.resize(32);
        void* privPtr = m_serverStaticPrivateKey.data();
        size_t privSize = m_serverStaticPrivateKey.size();

#ifdef Q_OS_WIN
        VirtualLock(privPtr, privSize);
#else
        mlock(privPtr, privSize);
        madvise(privPtr, privSize, MADV_DONTDUMP);
#endif

        std::random_device rd;
        quint32* ptr = reinterpret_cast<quint32*>(m_serverStaticPrivateKey.data());
        size_t num_words = m_serverStaticPrivateKey.size() / sizeof(quint32);
        for (size_t i = 0; i < num_words; ++i) {
            ptr[i] = rd();
        }

        NoiseDHState* dh = 0;
        noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
        noise_dhstate_set_keypair_private(
            dh, 
            reinterpret_cast<const uint8_t*>(m_serverStaticPrivateKey.constData()), 
            privSize
        );

        m_serverStaticPublicKey.fill(0);
        m_serverStaticPublicKey.resize(32);
        noise_dhstate_get_public_key(
            dh,
            reinterpret_cast<uint8_t*>(m_serverStaticPublicKey.data()),
            32);
        noise_dhstate_free(dh);

        ensurePublicKeyFilePresent();
        refreshPublicKeyWatcher();
        // --- END DYNAMIC KEY GENERATION ---

        if (!listen(QHostAddress::LocalHost, port))
        {
            PLog::Instance()->Log(TERROR, MODABPSERVER,
                                  "PolicyServer listen failed: %s",
                                  errorString().toUtf8().constData());
            return false;
        }

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer started on port %d", port);
        m_running = true;

        m_lastLoginState = !CCachedStore::GetClientIsLoggedOut();
        m_lastPolicy = CCachedStore::GetJiospherePolicy();
        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer primed state on start");

        // Start checking for updates every 500ms
        m_updateTimer->start(500);

        return true;
    }

    void stop()
    {
        if (!m_running)
            return;

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer stopping");

        close();

        foreach (QTcpSocket *sock, m_clients)
        {
            if (sock)
            {
                sock->disconnectFromHost();
                sock->deleteLater();
            }
        }

        m_clients.clear();
        m_subscribers.clear();
        m_requestBuffer.clear();
        foreach (NoiseSession *session, m_sessions)
        {
            delete session;
        }
        m_sessions.clear();
        m_updateTimer->stop();
        m_running = false;
        m_keyFileWatcher->removePaths(m_keyFileWatcher->files());
        m_keyFileWatcher->removePaths(m_keyFileWatcher->directories());

        // Wipe private key
        if (!m_serverStaticPrivateKey.isEmpty()) {
#ifdef Q_OS_WIN
            SecureZeroMemory(m_serverStaticPrivateKey.data(), m_serverStaticPrivateKey.size());
            VirtualUnlock(m_serverStaticPrivateKey.data(), m_serverStaticPrivateKey.size());
#else
            memset(m_serverStaticPrivateKey.data(), 0, m_serverStaticPrivateKey.size());
            __asm__ __volatile__ ("" : : "r"(m_serverStaticPrivateKey.data()) : "memory"); 
            munlock(m_serverStaticPrivateKey.data(), m_serverStaticPrivateKey.size());
#endif
            m_serverStaticPrivateKey.clear();
        }
        m_serverStaticPublicKey.clear();

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer stopped");
    }

    bool isRunning() const
    {
        return m_running;
    }

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        if (!m_running)
            return;

        QTcpSocket *socket = new QTcpSocket(this);

        if (!socket->setSocketDescriptor(socketDescriptor))
        {
            PLog::Instance()->Log(TERROR, MODABPSERVER,
                                  "Failed to set socket descriptor");
            socket->deleteLater();
            return;
        }

        m_clients.append(socket);

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "New client connected");

        connect(socket, SIGNAL(readyRead()),
                this, SLOT(onReadyRead()));
        connect(socket, SIGNAL(disconnected()),
                this, SLOT(onDisconnected()));
    }

private slots:
    void onReadyRead()
    {
        QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
        if (!socket)
            return;

        m_requestBuffer[socket].append(socket->readAll());

        if (!m_requestBuffer[socket].contains("\r\n\r\n"))
            return;

        QByteArray request = m_requestBuffer.take(socket);

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "Full HTTP request received");

        handleRequest(socket, QString::fromUtf8(request));
    }

    void onDisconnected()
    {
        QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
        if (!socket)
            return;

        m_clients.removeAll(socket);
        m_subscribers.removeAll(socket);
        m_requestBuffer.remove(socket);
        delete m_sessions.take(socket);

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "Client disconnected");

        socket->deleteLater();
    }

    void checkForUpdates()
    {
        ensurePublicKeyFilePresent();

        bool currentLoginState = !CCachedStore::GetClientIsLoggedOut();
        QString currentPolicy = CCachedStore::GetJiospherePolicy();

        // Check if anything changed
        if (currentLoginState == m_lastLoginState && currentPolicy == m_lastPolicy)
        {
            return;
        }

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "State change detected");

        // Update cache
        m_lastLoginState = currentLoginState;
        m_lastPolicy = currentPolicy;

        // Broadcast to all subscribers
        broadcastUpdate(currentLoginState, currentPolicy, "timer-change");
    }

private:
    explicit AccopsBrowserPolicyServer(QObject *parent)
        : QTcpServer(parent),
          m_running(false),
          m_updateTimer(new QTimer(this)),
          m_keyFileWatcher(new QFileSystemWatcher(this)),
          m_lastLoginState(false),
          m_streamEventCounter(0)
    {
        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer instance created");

        connect(m_updateTimer, SIGNAL(timeout()), this, SLOT(checkForUpdates()));
        connect(m_keyFileWatcher, SIGNAL(fileChanged(QString)),
                this, SLOT(onPublicKeyFileChanged(QString)));
        connect(m_keyFileWatcher, SIGNAL(directoryChanged(QString)),
                this, SLOT(onPublicKeyDirectoryChanged(QString)));
    }

    AccopsBrowserPolicyServer(const AccopsBrowserPolicyServer &);
    AccopsBrowserPolicyServer &operator=(const AccopsBrowserPolicyServer &);

    void ensurePublicKeyFilePresent()
    {
        if (m_serverStaticPublicKey.isEmpty())
            return;

        const QString filePath = publicKeyFilePath();
        QDir keyDir(QFileInfo(filePath).absolutePath());
        if (!keyDir.exists())
            keyDir.mkpath(".");

        const QByteArray expectedContents = m_serverStaticPublicKey.toHex();
        QFile pubFile(filePath);
        bool needsRewrite = true;
        if (pubFile.exists() && pubFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            needsRewrite = pubFile.readAll().trimmed() != expectedContents;
            pubFile.close();
        }

        if (!needsRewrite)
        {
            refreshPublicKeyWatcher();
            return;
        }

        if (pubFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        {
            pubFile.write(expectedContents);
            pubFile.close();
            PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                                  "Service Key ensured at %s",
                                  filePath.toUtf8().constData());
        }
        else
        {
            PLog::Instance()->Log(TERROR, MODABPSERVER,
                                  "Failed to write Service Key at %s",
                                  filePath.toUtf8().constData());
        }

        refreshPublicKeyWatcher();
    }

    void refreshPublicKeyWatcher()
    {
        const QString filePath = publicKeyFilePath();
        const QString dirPath = QFileInfo(filePath).absolutePath();

        if (!m_keyFileWatcher->directories().contains(dirPath))
            m_keyFileWatcher->addPath(dirPath);

        if (QFileInfo::exists(filePath) &&
            !m_keyFileWatcher->files().contains(filePath))
        {
            m_keyFileWatcher->addPath(filePath);
        }
    }

private slots:
    void onPublicKeyFileChanged(const QString &)
    {
        ensurePublicKeyFilePresent();
    }

    void onPublicKeyDirectoryChanged(const QString &)
    {
        ensurePublicKeyFilePresent();
    }

    void handleRequest(QTcpSocket *socket, const QString &request)
    {
        QStringList lines = request.split("\r\n");
        if (lines.isEmpty())
            return;

        QStringList first = lines.first().split(" ");
        if (first.size() < 2)
            return;

        QString method = first.at(0);
        QString path = first.at(1);
        const QString clientHandshakeB64 =
            extractHeaderValue(lines, QString::fromLatin1(kNoiseHandshakeHeader));

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "HTTP %s %s",
                              method.toUtf8().constData(),
                              path.toUtf8().constData());

        QByteArray body;

        if (method == "GET" && (path == "/streamPluginPolicy" || path == "/ClientStatus"))
        {
            QByteArray clientHandshake;
            QByteArray serverHandshake;
            NoiseSession *session = 0;

            if (clientHandshakeB64.isEmpty() ||
                m_serverStaticPrivateKey.isEmpty() ||
                (clientHandshake = QByteArray::fromBase64(clientHandshakeB64.toLatin1())).isEmpty())
            {
                PLog::Instance()->Log(TERROR, MODABPSERVER,
                                      "Connection rejected: missing required parameters");
                body =
                    "{"
                    "\"status\":\"error\","
                    "\"message\":\"Secure connection required\""
                    "}";
                socket->write(buildResponse(body, 400, "Bad Request"));
                socket->disconnectFromHost();
                return;
            }

            session = new NoiseSession();
            if (!session->InitializeResponder(m_serverStaticPrivateKey) ||
                !session->ReadHandshakeMessage(clientHandshake) ||
                !session->WriteHandshakeMessage(serverHandshake) ||
                !session->isReady())
            {
                PLog::Instance()->Log(TERROR, MODABPSERVER,
                                      "Connection rejected: validation failed");
                delete session;
                body =
                    "{"
                    "\"status\":\"error\","
                    "\"message\":\"Secure connection failed\""
                    "}";
                socket->write(buildResponse(body, 400, "Bad Request"));
                socket->disconnectFromHost();
                return;
            }

            PLog::Instance()->Log(TDEBUG, MODABPSERVER, "Client subscribed to policy stream");
            PLog::Instance()->Log(TDEBUG, MODABPSERVER, "Secure session established");

            // 1. Send SSE Headers
            QByteArray headers;
            headers.append("HTTP/1.1 200 OK\r\n");
            headers.append("Content-Type: text/event-stream\r\n");
            headers.append("Cache-Control: no-cache\r\n");
            headers.append("Connection: keep-alive\r\n");
            headers.append("Access-Control-Allow-Origin: *\r\n");
            headers.append("Access-Control-Allow-Methods: GET\r\n");
            headers.append("Access-Control-Allow-Headers: Content-Type\r\n");
            headers.append(kNoiseHandshakeHeader);
            headers.append(": ");
            headers.append(serverHandshake.toBase64());
            headers.append("\r\n");
            headers.append("X-Accel-Buffering: no\r\n");
            headers.append("\r\n");

            socket->write(headers);
            socket->flush();

            // 2. Add to subscribers list for future updates
            m_subscribers.append(socket);
            m_sessions.insert(socket, session);

            // 3. Send IMMEDIATE current state (Bootstrap)
            bool isLoggedOut = CCachedStore::GetClientIsLoggedOut();
            QString policy = CCachedStore::GetJiospherePolicy();

            // Sync local cache to avoid immediate duplicate broadcast if timer ticks
            m_lastLoginState = !isLoggedOut;
            m_lastPolicy = policy;

            sendSSEEvent(socket, !isLoggedOut, policy, "bootstrap");

            // DO NOT CLOSE SOCKET - It needs to stay open for the stream
            return;
        }
        else
        {
            body =
                "{"
                "\"status\":\"error\","
                "\"message\":\"Not Found\""
                "}";

            socket->write(buildResponse(body, 404, "Not Found"));
        }

        socket->disconnectFromHost();
    }

    void broadcastUpdate(bool isLoggedIn, const QString &policy, const char *source)
    {
        if (m_subscribers.isEmpty())
            return;

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "Broadcasting update to subscribers");

        QMutableListIterator<QTcpSocket *> i(m_subscribers);
        while (i.hasNext())
        {
            QTcpSocket *socket = i.next();
            if (socket->state() == QAbstractSocket::ConnectedState)
            {
                sendSSEEvent(socket, isLoggedIn, policy, source);
            }
            else
            {
                i.remove(); // Cleanup dead sockets
            }
        }
    }

    void sendSSEEvent(QTcpSocket *socket,
                      bool isLoggedIn,
                      const QString &policy,
                      const char *source)
    {
        NoiseSession *session = m_sessions.value(socket, 0);
        if (!session || !session->isReady())
            return;

        QByteArray policyData;
        QByteArray normalizedPolicyJson;
        QByteArray parseMode;
        bool normalized = false;
        if (!isLoggedIn)
        {
            normalizedPolicyJson = "{}";
            policyData = normalizedPolicyJson.toBase64();
            parseMode = "logged-out";
            normalized = true;
        }
        else
        {
            normalized = normalizePolicyForWire(policy, policyData,
                                                normalizedPolicyJson, parseMode);
        }

        QByteArray innerJson;
        innerJson.append("{");
        innerJson.append("\"policydata\":\"");
        innerJson.append(policyData);
        innerJson.append("\",");
        innerJson.append("\"loginStatus\":");
        innerJson.append(isLoggedIn ? "true" : "false");
        innerJson.append("}");

        QByteArray encryptedPayload;
        if (!session->Encrypt(innerJson, encryptedPayload))
        {
            PLog::Instance()->Log(TERROR, MODABPSERVER,
                                  "Stream send failed: payload creation error");
            return;
        }

        QByteArray body;
        body.append("{");
        body.append("\"awcData\":\"");
        body.append(encryptedPayload.toBase64());
        body.append("\"}");

        QByteArray payload;
        payload.append("data: ");
        payload.append(body);
        payload.append("\n\n"); // SSE Event Terminator

        ++m_streamEventCounter;
        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "Stream event sent");

        // Securely clear sensitive buffers before they are deallocated
        normalizedPolicyJson.fill('\0');
        innerJson.fill('\0');

        socket->write(payload);
        socket->flush();
    }

    QByteArray buildResponse(const QByteArray &body,
                             int status,
                             const QByteArray &text)
    {
        QByteArray resp;
        resp.append("HTTP/1.1 ");
        resp.append(QByteArray::number(status));
        resp.append(" ");
        resp.append(text);
        resp.append("\r\n");
        resp.append("Content-Type: application/json\r\n");
        resp.append("Content-Length: ");
        resp.append(QByteArray::number(body.size()));
        resp.append("\r\n");
        resp.append("Connection: close\r\n\r\n");
        resp.append(body);
        return resp;
    }

private:
    bool m_running;
    QList<QTcpSocket *> m_clients;
    QList<QTcpSocket *> m_subscribers;
    QTimer *m_updateTimer;
    QFileSystemWatcher *m_keyFileWatcher;
    QString m_lastPolicy;
    bool m_lastLoginState;
    quint64 m_streamEventCounter;
    QHash<QTcpSocket *, QByteArray> m_requestBuffer;
    QHash<QTcpSocket *, NoiseSession *> m_sessions;
    QByteArray m_serverStaticPrivateKey;
    QByteArray m_serverStaticPublicKey;
};

#endif // ACCOPSBROWSERPOLICYSERVER_H
