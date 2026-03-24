
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
#include "PLog.h"
#include "CommonUIHandler.h"
#include "NoiseSession.h"

namespace
{
const char kNoiseHandshakeHeader[] = "X-Noise-Handshake";
const char kServerStaticPrivateKeyHex[] =
    "0891788b41a01205a25bcbbea3b735e30077a3715d6f5da50cf0974e91de9a7f";

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

bool loadServerStaticPrivateKey(QByteArray &privateKey)
{
    privateKey = QByteArray::fromHex(kServerStaticPrivateKeyHex);
    return privateKey.size() == 32;
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
                              "PolicyServer primed state on start: Login=%d, PolicyLen=%d",
                              m_lastLoginState, m_lastPolicy.length());

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
                              "Full HTTP request received (%d bytes)",
                              request.size());

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
        bool currentLoginState = !CCachedStore::GetClientIsLoggedOut();
        QString currentPolicy = CCachedStore::GetJiospherePolicy();

        // Check if anything changed
        if (currentLoginState == m_lastLoginState && currentPolicy == m_lastPolicy)
        {
            return;
        }

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "State change detected: Login=%d, PolicyLen=%d",
                              currentLoginState, currentPolicy.length());

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
          m_lastLoginState(false),
          m_streamEventCounter(0)
    {
        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer instance created");

        connect(m_updateTimer, SIGNAL(timeout()), this, SLOT(checkForUpdates()));
    }

    AccopsBrowserPolicyServer(const AccopsBrowserPolicyServer &);
    AccopsBrowserPolicyServer &operator=(const AccopsBrowserPolicyServer &);

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
            QByteArray serverStaticPrivateKey;
            QByteArray clientHandshake;
            QByteArray serverHandshake;
            NoiseSession *session = 0;

            if (clientHandshakeB64.isEmpty() ||
                !loadServerStaticPrivateKey(serverStaticPrivateKey) ||
                (clientHandshake = QByteArray::fromBase64(clientHandshakeB64.toLatin1())).isEmpty())
            {
                PLog::Instance()->Log(TERROR, MODABPSERVER,
                                      "Noise handshake rejected: missing/invalid client handshake");
                body =
                    "{"
                    "\"status\":\"error\","
                    "\"message\":\"Noise handshake required\""
                    "}";
                socket->write(buildResponse(body, 400, "Bad Request"));
                socket->disconnectFromHost();
                return;
            }

            session = new NoiseSession();
            if (!session->InitializeResponder(serverStaticPrivateKey) ||
                !session->ReadHandshakeMessage(clientHandshake) ||
                !session->WriteHandshakeMessage(serverHandshake) ||
                !session->isReady())
            {
                serverStaticPrivateKey.fill('\0'); // Clear private key on failure
                PLog::Instance()->Log(TERROR, MODABPSERVER,
                                      "Noise handshake failed: clientHandshakeBytes=%d",
                                      clientHandshake.size());
                delete session;
                body =
                    "{"
                    "\"status\":\"error\","
                    "\"message\":\"Noise handshake failed\""
                    "}";
                socket->write(buildResponse(body, 400, "Bad Request"));
                socket->disconnectFromHost();
                return;
            }
            
            // Clear the private key from memory ASAP after successful initialization
            serverStaticPrivateKey.fill('\0');

            PLog::Instance()->Log(TDEBUG, MODABPSERVER, "Client subscribed to policy stream");
            PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                                  "Noise handshake accepted: clientHandshakeBytes=%d serverHandshakeBytes=%d",
                                  clientHandshake.size(), serverHandshake.size());

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
                              "Broadcasting update to %d subscribers, source=%s, login=%d",
                              m_subscribers.size(), source, isLoggedIn);

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
                                  "STREAM send failed: source=%s encrypt failed", source);
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
                              "STREAM event=%llu source=%s login=%d normalized=%d parseMode=%s",
                              static_cast<unsigned long long>(m_streamEventCounter),
                              source, isLoggedIn, normalized, parseMode.constData());

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
    QString m_lastPolicy;
    bool m_lastLoginState;
    quint64 m_streamEventCounter;
    QHash<QTcpSocket *, QByteArray> m_requestBuffer;
    QHash<QTcpSocket *, NoiseSession *> m_sessions;
};

#endif // ACCOPSBROWSERPOLICYSERVER_H
