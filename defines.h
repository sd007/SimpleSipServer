#ifndef DEFINES_H
#define DEFINES_H

/* Include all headers. */
#include <pjlib.h>
#include <pjsip.h>
#include <stdlib.h>
#include <pjsip-simple/publish.h>
#include <pjlib-util.h>
#include <pjsip_ua.h>
#include <pjsip/sip_uri.h>
#include <pjsip/sip_transport.h>
#include <pjsip/sip_types.h>
#include <pjmedia.h>
#include <pjmedia/sdp_neg.h>
#include <pjmedia/sdp.h>
#include <stdlib.h>
#include <QString>


typedef struct tagTransportContext
{
    QString sipDomain;
    QString fromID;
    QString fromIP;
    unsigned short fromPort;

    QString toID;
    QString toIP;
    unsigned short toPort;

    QString contactID;
    QString contactIP;
    unsigned short contactPort;

    tagTransportContext(){
        fromPort = 5060;
        toPort = 5060;
        contactPort = 5060;
    }
}TransportContext;


typedef struct tagSIPServer
{
    QString sipserverID;
    QString sipserverDomain;
    QString sipserverPasswd;
    unsigned short sipserverPort;
    unsigned int heartbeatInterval;
    unsigned int maxTimeoutCount;
    tagSIPServer(){
        sipserverPort = 5060;
        heartbeatInterval = 60;
        maxTimeoutCount = 5;
    }
}SIPServer;

typedef struct tagSIPClient
{
    QString sipserverID;
    QString sipserverDomain;
    QString sipserverAddress; //ip
    unsigned short sipserverPort;

    QString localDeviceID;
    QString localAddress; //ip
    unsigned short localSipPort;
    QString localPasswd;
    unsigned long regValidSeconds; //s

    unsigned int heartbeatInterval;
    unsigned int maxTimeoutCount;
    tagSIPClient(){
        sipserverAddress = "172.0.0.1";
        localPasswd = "12345678";
        sipserverPort = 5060;
        localSipPort = 5060;
        regValidSeconds = 86400;
        heartbeatInterval = 60;
        maxTimeoutCount = 3;
    }
}SIPClient;

typedef enum{
    TYPE_None,
    TYPE_SIPServer,
    TYPE_SIPClient,
    TYPE_Other
}LocalSipType;

/* Application's global variables */
//typedef struct tagParamNode
//{
//    LocalSipType localSipType;
//    union{
//        SIPServer sipServer;
//        SIPClient sipClient;
//    };

//    pj_caching_pool	 caching_pool;
//    pj_pool_t		*pool;

//    pjsip_endpoint	*sip_endpt;
//    pjmedia_endpt	*media_endpt;

//    pj_bool_t		 thread_quit;
//    pj_thread_t		*sip_thread[1];
//}ParamNode;


#endif // DEFINES_H
