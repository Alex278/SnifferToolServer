#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QObject>
#include "pcapcommon.h"

// 鼠标相关
#define MARGIN 5


namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

// Pcap相关
private:
    PcapCommon *pcap;

// Widget相关
private:
    Ui::Widget *ui;

private:
// TabWidget面板相关
    void tabWidgetPanelInit();
// TabView初始化
    void tabViewInit();
// ComboboxAdapter初始化
    void comboboxAdapterInit();

// 鼠标和窗口相关
private:
    bool isLeftPressed;
    int curPos;
    QPoint pLast;
    int countFlag(QPoint p, int row);
    void setCursorType(int flag);
    int countRow(QPoint p);
    void mouseAndWinInit();
protected:
    void mousePressEvent(QMouseEvent *event);
    void mouseReleaseEvent(QMouseEvent *event);
    void mouseDoubleClickEvent(QMouseEvent *event);
    void mouseMoveEvent(QMouseEvent *event);
private slots:
    void on_minButton_clicked();
    void on_maxButton_clicked();
    void on_closeButton_clicked();

    void on_ComboBoxAdapter_currentIndexChanged(const QString &arg1);
    void on_pushButtonOpenAdapter_clicked();

    void on_pushButtonStartScan_clicked();

public slots:
    // 获取本机Mac地址完成槽函数处理
    void getSelfMacFinishedSlot(QString mac);

};

#endif // WIDGET_H
