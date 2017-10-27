#ifndef MEDIACLIENT_H
#define MEDIACLIENT_H

#include <QObject>
#include <QMap>
#include <QLabel>
#include <QLineEdit>
#include <QWidget>
#include <QPushButton>
#include <QByteArray>
#include <QTimer>
#include "defines.h"
#include "rtprecver.h"
#include "decoder/decoder.h"
#include "imagelabel.h"


class MediaClient : public QWidget
{
    Q_OBJECT
public:
    explicit MediaClient(QWidget *parent = 0);
    ~MediaClient();
public:
    void setUpUI();
    void initDecoder();
    void setServerParamContext();
    pj_status_t initPJlib();
    pj_status_t initSipMoudle(QString endptName);
    pj_status_t registerClient(SIPClient &cltparam);
    void quit();
    void startEventLoop();

    bool sendInvite(QString deviceid, QString mediaRecvIp, short mediaRecvPort);
    int sendBye();
    void queryDeviveInfo(QString deviceid, QString cmdType = QString("Catalog"));
    //thread
    static int eventloop_thread(void *arg);
    //callback
    static pj_bool_t on_rx_request( pjsip_rx_data *rdata );
private:
    QString createPlaySDP(QString fromDeviceid, QString mediaRecvIp, unsigned short mediaRecvPort);
    int initInvParam(TransportContext &tsxContext);
    void messageResolve(char *txt);
private:
    TransportContext m_tsxContext;
    SIPClient m_sipClientparam;
    pjsip_dialog *m_invitedlg  = Q_NULLPTR;
    pjsip_inv_session *m_invsession = Q_NULLPTR;

    pj_caching_pool m_caching_pool;
    pj_pool_t *m_sipPool;

    static pjsip_endpoint *m_sipEndpt;
    static bool quit_flag;
    bool m_invInit = false;
    pj_thread_t *m_eventloopthread = Q_NULLPTR;
    LocalSipType m_localSipType;
    //ui
    QWidget *m_widget;
    QLabel *m_lblocalip;
    QLineEdit *m_edlocalip;

    QLabel *m_lbServid;
    QLineEdit *m_edServid;
    QLabel *m_lbServSipport;
    QLineEdit *m_edServSipport;

    QLabel *m_lbclientip;
    QLineEdit *m_edclientip;
    QLabel *m_lbClientID;
    QLineEdit *m_edClientID;
    QLabel *m_lbclientSipport;
    QLineEdit *m_edclientSipport;

    QLabel *m_lbmediarecvip;
    QLineEdit *m_edmediarecvip;
    QLabel *m_lbmediarecvport;
    QLineEdit *m_edmediarecvport;

    ImageLabel *m_imgLabel;

    QLabel *m_lbmediaDeviceId;
    QLineEdit *m_edmediaDeviceId;

    QPushButton *m_btplay;
    QPushButton *m_btstop;
    //decoder
    RtpRecver *m_rtpRecver  = Q_NULLPTR;
    Decoder *m_avDecoder  = Q_NULLPTR;
    static QMap<QString,TransportContext> m_tsxContextMap;
signals:

public slots:
    void onStop();
    void onPlay();
    void onRecvedFrame(QByteArray buff);
};

#endif // MEDIACLIENT_H
