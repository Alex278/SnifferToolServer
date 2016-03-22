#-------------------------------------------------
#
# Project created by QtCreator 2016-03-09T15:44:07
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SnifferTool
TEMPLATE = app


#-------------------------------------------------

QMAKE_CFLAGS += -std=gnu11  -D_GNU_SOURCE
QMAKE_CXXFLAGS += -std=gnu++11

#-------------------------------------------------
# WinPcap
INCLUDEPATH += D:\WinPcap\Include
LIBS += -LD:/WinPcap/Lib/ -lpacket -lwpcap

# WinSock
LIBS += -lws2_32
LIBS += -liphlpapi
#-------------------------------------------------
# libnet
#LIBS += -L$$PWD/libnet/Lib/ -lnet
#INCLUDEPATH +=$$PWD/libnet/Include
#DEPENDPATH +=$$PWD/libnet/Include
LIBS += -LD:/WinPcap/libnet/Lib/ -lnet
INCLUDEPATH += D:\WinPcap\libnet\Include
#-------------------------------------------------


SOURCES += main.cpp\
        widget.cpp \
    NoFocusDelegate.cpp \
    pcapcommon.cpp \
    getmacthread.cpp \
    tcpipprotocol.cpp \
    sendpacketthread.cpp \
    receivepacketthread.cpp \
    trafficstatistic.cpp \
    filterthread.cpp \
    getallhostname.cpp \
    libping.cpp \
    syn_scan.cpp \
    portservicemap.cpp

HEADERS  += widget.h \
    tcpipcommon.h \
    NoFocusDelegate.h \
    pcapcommon.h \
    getmacthread.h \
    tcpipprotocol.h \
    sendpacketthread.h \
    receivepacketthread.h \
    trafficstatistic.h \
    filterthread.h \
    getallhostname.h \
    libping.h \
    syn_scan.h \
    portservicemap.h

FORMS    += widget.ui

DISTFILES += \
    readme.txt
