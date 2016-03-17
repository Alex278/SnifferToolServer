#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QObject>
#include <QPair>
#include <QMetaType>
#include <QMenu>
#include <QTableWidgetItem>
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
// TabWidget初始化
    void tabWidgetInit();
// ComboboxAdapter初始化
    void comboboxAdapterInit();
// 新增一个主机信息到tableWidget
    void addANewHost(QPair<QString,QString> info);
// 从tablewidge中，通过网关ip获取网关mac
    QString getGatewayMacFromTabWidget();
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
    void on_pushButtonApplyFilter_clicked();
    void on_pushButtonStopFilter_clicked();

public slots:
    // 获取本机Mac地址完成槽函数处理
    void getSelfMacFinishedSlot(QString mac);
    // 扫描主机结束
    void scanHostFinishedSlot();
    // 接收当前正在扫描的ip地址
    void scanCurrentIpSlot(QString);
    // 接收扫描到的主机信息
    void scanGetHostInfoSlot(QPair<QString,QString>);
    // tab 单元格双击槽函数
    void tablItemDoubleClickedSlot(QTableWidgetItem *item);
    // tab 鼠标进入item
    void itemEnteredHover(QTableWidgetItem *);
    // 获取网速
    void trafficStatisticNetSpeedSlot(QString);
    // 获取filter发送的数据
    void filterUpdateDataSlot(QString data);
};

#endif // WIDGET_H
