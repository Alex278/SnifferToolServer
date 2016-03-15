#include "bufferthread.h"

BufferThread::BufferThread(QObject *parent) : QObject(parent)
{

}

// 接收扫描到的主机信息
void BufferThread::scanGetHostInfoSlot(QPair<QString,QString>)
{

}
