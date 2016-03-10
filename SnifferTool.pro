#-------------------------------------------------
#
# Project created by QtCreator 2016-03-09T15:44:07
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SnifferTool
TEMPLATE = app

INCLUDEPATH += E:\WinPcapLib\Include
LIBS += -LE:/WinPcapLib/Lib/   -lPacket -lwpcap


SOURCES += main.cpp\
        widget.cpp \
    NoFocusDelegate.cpp \
    pcapcommon.cpp

HEADERS  += widget.h \
    tcpipcommon.h \
    NoFocusDelegate.h \
    pcapcommon.h

FORMS    += widget.ui
