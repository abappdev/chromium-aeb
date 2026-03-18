
#ifndef ACCOPSBROWSERPOLICYSERVER_H
#define ACCOPSBROWSERPOLICYSERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QStringList>
#include <QHostAddress>
#include <QList>
#include <QHash>
#include <QTimer>
#include <QtGlobal>
#include "PLog.h"
#include "CommonUIHandler.h"

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

        if (!listen(QHostAddress::AnyIPv4, port))
        {
            PLog::Instance()->Log(TERROR, MODABPSERVER,
                                  "PolicyServer listen failed: %s",
                                  errorString().toUtf8().constData());
            return false;
        }

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "PolicyServer started on port %d", port);
        m_running = true;

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
        broadcastUpdate(currentLoginState, currentPolicy);
    }

private:
    explicit AccopsBrowserPolicyServer(QObject *parent)
        : QTcpServer(parent),
          m_running(false),
          m_updateTimer(new QTimer(this)),
          m_lastLoginState(false)
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

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "HTTP %s %s",
                              method.toUtf8().constData(),
                              path.toUtf8().constData());

        QByteArray body;

        if (method == "GET" && (path == "/streamPluginPolicy" || path == "/ClientStatus"))
        {
            PLog::Instance()->Log(TDEBUG, MODABPSERVER, "Client subscribed to policy stream");

            // 1. Send SSE Headers
            QByteArray headers;
            headers.append("HTTP/1.1 200 OK\r\n");
            headers.append("Content-Type: text/event-stream\r\n");
            headers.append("Cache-Control: no-cache\r\n");
            headers.append("Connection: keep-alive\r\n");
            headers.append("Access-Control-Allow-Origin: *\r\n");
            headers.append("Access-Control-Allow-Methods: GET\r\n");
            headers.append("Access-Control-Allow-Headers: Content-Type\r\n");
            headers.append("X-Accel-Buffering: no\r\n");
            headers.append("\r\n");

            socket->write(headers);
            socket->flush();

            // 2. Add to subscribers list for future updates
            m_subscribers.append(socket);

            // 3. Send IMMEDIATE current state (Bootstrap)
            bool isLoggedOut = CCachedStore::GetClientIsLoggedOut();
            QString policy = CCachedStore::GetJiospherePolicy();

            // Sync local cache to avoid immediate duplicate broadcast if timer ticks
            m_lastLoginState = !isLoggedOut;
            m_lastPolicy = policy;

            sendSSEEvent(socket, !isLoggedOut, policy);

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

    void broadcastUpdate(bool isLoggedIn, const QString &policy)
    {
        if (m_subscribers.isEmpty())
            return;

        PLog::Instance()->Log(TDEBUG, MODABPSERVER,
                              "Broadcasting update to %d subscribers", m_subscribers.size());

        QMutableListIterator<QTcpSocket *> i(m_subscribers);
        while (i.hasNext())
        {
            QTcpSocket *socket = i.next();
            if (socket->state() == QAbstractSocket::ConnectedState)
            {
                sendSSEEvent(socket, isLoggedIn, policy);
            }
            else
            {
                i.remove(); // Cleanup dead sockets
            }
        }
    }

    void sendSSEEvent(QTcpSocket *socket, bool isLoggedIn, const QString &policy)
    {
        QByteArray policyData;
        if (!isLoggedIn || policy.isEmpty())
        {
            policyData = "e30="; // {} base64
        }
        else
        {
            policyData = policy.toUtf8();
        }

        QByteArray body;
        body.append("{");
        body.append("\"status\":\"success\",");
        body.append("\"policydata\":\"");
        body.append(policyData);
        body.append("\",");
        body.append("\"loginStatus\":");
        body.append(isLoggedIn ? "true" : "false");
        body.append("}");

        QByteArray payload;
        payload.append("data: ");
        payload.append(body);
        payload.append("\n\n"); // SSE Event Terminator

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
    QHash<QTcpSocket *, QByteArray> m_requestBuffer;
};

#endif // ACCOPSBROWSERPOLICYSERVER_H
