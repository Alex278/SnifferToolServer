#ifndef BUFFERTHREAD_H
#define BUFFERTHREAD_H

// 1）信号量实现缓冲区的存取，两个线程，一个线程存，一个线程取，并emit到UI，存在全局变量和全局信号量或者互斥锁
// 2) 一个缓冲线程，使用队列缓冲，定时器中断取数据，并emit到UI，无全局变量，但是只适合小量数据缓冲


#include <QObject>
#include <QMetaType>

class BufferThread : public QObject
{
    Q_OBJECT
public:
    explicit BufferThread(QObject *parent = 0);

signals:

public slots:
    // 接收扫描到的主机信息
    void scanGetHostInfoSlot(QPair<QString,QString>);
};

#endif // BUFFERTHREAD_H
