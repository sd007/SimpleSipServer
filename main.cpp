#include <QApplication>
#include "mediaclient.h"
#include <QThread>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MediaClient mlient;
    mlient.setUpUI();
    mlient.setServerParamContext();

    mlient.initPJlib();
    mlient.initSipMoudle("simple_sipserver_enpt");
    mlient.startEventLoop();

    mlient.initDecoder();
    mlient.show();
    qDebug()<<"started";
    return app.exec();
}






