#include "widget.h"
#include "ui_widget.h"
#include <QMouseEvent>
#include <QDebug>
#include "NoFocusDelegate.h"
#include "getallhostname.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    aboutDialog = new AboutDialog(this);
    aboutDialog->setModal(true);
    // 注册自定义结构参数
    qRegisterMetaType< QPair<QString,QString> >("QPair<QString,QString>");

    mouseAndWinInit();
    tabWidgetPanelInit();
    tabWidgetInit();
    ui->pushButtonStartScan->setEnabled(false);

    pcap = new PcapCommon();
    pcap->winSocketInit();

    connect(pcap,SIGNAL(getSelfMacFinishedSig(QString)),this,SLOT(getSelfMacFinishedSlot(QString)));
    connect(pcap,SIGNAL(scanHostFinishedSig()),this,SLOT(scanHostFinishedSlot()));
    connect(pcap,SIGNAL(scanCurrentIpSig(QString)),this,SLOT(scanCurrentIpSlot(QString)));
    connect(pcap,SIGNAL(scanGetHostInfoSig(QPair< QString,QString >)),this,SLOT(scanGetHostInfoSlot(QPair< QString,QString >)));
    connect(pcap,SIGNAL(trafficStatisticNetSpeedSig(QString)),this,SLOT(trafficStatisticNetSpeedSlot(QString)));
    connect(pcap,SIGNAL(filterUpdateDataSig(QString)),this,SLOT(filterUpdateDataSlot(QString)));
    connect(pcap,SIGNAL(filterStatusSig(int,QString)),this,SLOT(filterStatusSlot(int,QString)));
    connect(pcap,SIGNAL(pingUpdateEchoSig(QString)),this,SLOT(pingUpdateEchoSlot(QString)));
    connect(pcap,SIGNAL(portScanIsFinishedSig()),this,SLOT(portScanIsFinishedSlot()));
    connect(pcap,SIGNAL(portScanRecvUpdataSig(QString)),this,SLOT(portScanRecvUpdataSlot(QString)));

    // getHostnameTimer init
    getHostnameTimer = new QTimer();
    connect(getHostnameTimer,SIGNAL(timeout()),this,SLOT(getHostnameFromQQueueBufferSlot()));
    getHostnameTimer->start(100);

    comboboxAdapterInit();
}

Widget::~Widget()
{
    delete ui;
}

// tabWidget面板初始化
void Widget::tabWidgetPanelInit()
{
    ui->tabWidget->setTabPosition(QTabWidget::West);

    //ui->tab0->setStyleSheet("border: 0px;");
    //ui->tab1->setStyleSheet("border: 0px;");

    for(int i = 0; i < 2; i++){
        QToolButton* tb = new QToolButton;
        tb->setStyleSheet("background-color: none; border: 0px;");
        tb->setAttribute(Qt::WA_TransparentForMouseEvents);
        tb->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
        ui->tabWidget->tabBar()->setTabButton(i,QTabBar::LeftSide,tb);
    }
}

// TabWidget初始化
void Widget::tabWidgetInit()
{
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->horizontalHeader()->setFixedHeight(35);
    QStringList header;
//    header <<tr("IP地址")<<tr("机器名")<<tr("上行带宽(KB/S)") << "下行带宽(KB/S)"
//           << tr("MAC地址") << tr("网卡描述") << tr("日流量");
    header << tr("IP地址") << tr("主机名") << tr("MAC地址") << tr("主机状态");
    ui->tableWidget->setHorizontalHeaderLabels(header);
    QFont font = ui->tableWidget->horizontalHeader()->font();
    font.setBold(true);
    ui->tableWidget->horizontalHeader()->setFont(font);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->setStyleSheet("selection-background-color:lightblue;");
    //ui->tableWidget->horizontalHeader()->setStyleSheet("QHeaderView::section{background:greenyellow;}");
    ui->tableWidget->horizontalHeader()->setHighlightSections(false);
    ui->tableWidget->setFrameShape(QFrame::NoFrame);
    //ui->tableWidget->verticalHeader()->hide();
    //ui->tableWidget->horizontalHeader()->resizeSection(0,150);
    //ui->tableWidget->horizontalHeader()->resizeSection(1,80);
    //ui->tableWidget->horizontalHeader()->resizeSection(2,160);
    //ui->tableWidget->horizontalHeader()->resizeSection(3,160);
    ui->tableWidget->setItemDelegate(new NoFocusDelegate());
    ui->tableWidget->setMouseTracking(true);
    connect(ui->tableWidget, SIGNAL(itemDoubleClicked(QTableWidgetItem *)),
            this, SLOT(tablItemDoubleClickedSlot(QTableWidgetItem *)));
    connect(ui->tableWidget,SIGNAL(itemEntered(QTableWidgetItem*)),
            this,SLOT(itemEnteredHover(QTableWidgetItem *)));
}

// combobox adapter 初始化
void Widget::comboboxAdapterInit()
{
    QVector<DEVInfo> devInfo(pcap->findAllDev());
    while(ui->ComboBoxAdapter->count() > 0){
        ui->ComboBoxAdapter->removeItem(0);
    }

    for(int i = 0; i < devInfo.length(); ++i){
        QPixmap icon  = style()->standardPixmap(QStyle::SP_DriveNetIcon);
        ui->ComboBoxAdapter->addItem(icon,devInfo.at(i).name);
    }
}

// 新增一个主机信息到tableWidget
void Widget::addANewHost(QPair< QString ,QString > info)
{
    // ip , hostname , mac , status
    QString infoArray[4] = {info.first,"------",info.second,tr("正常")};

    // 接收数据太快，获取的row有时间上误差，需建立缓冲区来新增主机信息
    ui->tableWidget->update();

    int row = ui->tableWidget->rowCount();


    if(row == 0){
        ui->tableWidget->insertRow(row);
        ui->labelHostNum->setText(QString::number(row+1));
        QPixmap icon  = style()->standardPixmap(QStyle::SP_DesktopIcon);
        for(int i = 0; i < (ui->tableWidget->columnCount()); ++i){
            QTableWidgetItem *item = new QTableWidgetItem(infoArray[i]);
            item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
            item->setFlags(item->flags() ^ Qt::ItemIsEditable);
            if(i == 0)item->setIcon(icon);

            ui->tableWidget->setItem(row,i,item);
        }
    }
    else {
        for(int i = 0;i < row; ++i){
            QString strText = ui->tableWidget->item(i,0)->text();            
            if(info.first == strText){
                return ;
            }
        }
        ui->tableWidget->insertRow(row);
        ui->labelHostNum->setText(QString::number(row+1));
        QPixmap icon  = style()->standardPixmap(QStyle::SP_ComputerIcon);

        for(int i = 0; i < (ui->tableWidget->columnCount()); ++i){
            QTableWidgetItem *item = new QTableWidgetItem(infoArray[i]);
            item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
            item->setFlags(item->flags() ^ Qt::ItemIsEditable);
            if(i == 0)item->setIcon(icon);            
            item->setToolTip(tr("双击行进行ARP Cheat!"));
            ui->tableWidget->setItem(row,i,item);
        }
    }
}

// 通过指定ip更新tablewidget中的主机名
void Widget::updateHostname(QString ip,QString hostname)
{
    for(int i = 0; i < ui->tableWidget->rowCount(); ++i){
        QTableWidgetItem *item =  ui->tableWidget->item(i,0);
        // 二次扫描的过程中不需要更新已经获取了主机名的主机
        if((item->text() == ip) && (ui->tableWidget->item(i,3)->text() != tr("ARP攻击中"))){
            ui->tableWidget->item(i,1)->setText(hostname);
            break;
        }
    }
}

// 从tablewidge中，通过网关ip获取网关mac
QString Widget::getGatewayMacFromTabWidget()
{
    QString gatewayIp = pcap->getGateway();

     int row = ui->tableWidget->rowCount();

     for(int i = 0;i < row; ++i){
         QString strText = ui->tableWidget->item(i,0)->text();
         if(gatewayIp == strText){
            return ui->tableWidget->item(i,2)->text();
         }
     }
     return "00-00-00-00-00-00";
}

//-----------------------------------------------------------
// 鼠标和窗口的初始化
//-----------------------------------------------------------
void Widget::mouseAndWinInit()
{
    // 获取最小化、关闭按钮图标
    QPixmap minPix  = style()->standardPixmap(QStyle::SP_TitleBarMinButton);
    QPixmap closePix = style()->standardPixmap(QStyle::SP_TitleBarCloseButton);
    QPixmap maxPix = style()->standardPixmap(QStyle::SP_TitleBarMaxButton);
    QPixmap setPix = style()->standardPixmap(QStyle::SP_TitleBarUnshadeButton);

    // 设置最小化、关闭按钮图标
    ui->minButton->setIcon(minPix);    
    ui->maxButton->setIcon(maxPix);
    ui->closeButton->setIcon(closePix);
    ui->setButton->setIcon(setPix);

    ui->minButton->setToolTip(tr("最小化"));
    ui->maxButton->setToolTip(tr("最大化"));
    ui->closeButton->setToolTip(tr("关闭"));
    ui->setButton->setToolTip(tr("关于"));
    // 窗口鼠标拖动相关
    // 设置主窗口无边框
    this->setWindowFlags(Qt::FramelessWindowHint);
    // 设置在不按鼠标的情况下也触发鼠标移动事件
    this->setMouseTracking(true);
    // 鼠标左键按下标记
    isLeftPressed = false;
    // 标记鼠标左击时的位置
    curPos = 0;
}

//-----------------------------------------------------------
// 窗口移动、缩放处理部分
//-----------------------------------------------------------
// 鼠标按下事件
void Widget::mousePressEvent(QMouseEvent *event)
{
    if(event->button()==Qt::LeftButton){
        this->isLeftPressed=true;
        QPoint temp=event->globalPos();
        pLast=temp;
        curPos=countFlag(event->pos(),countRow(event->pos()));
        event->ignore();
    }
}

// 鼠标释放事件
void Widget::mouseReleaseEvent(QMouseEvent *event)
{
    if(isLeftPressed)
        isLeftPressed=false;
    // 恢复鼠标指针形状
    QApplication::restoreOverrideCursor();
    event->ignore();
}

// 鼠标双击事件
void Widget::mouseDoubleClickEvent(QMouseEvent *event)
{
    if(event->button()==Qt::LeftButton){
        if(windowState()!=Qt::WindowFullScreen)
            // 双击窗口全屏
            setWindowState(Qt::WindowFullScreen);
        // 恢复正常模式
        else setWindowState(Qt::WindowNoState);
    }
    event->ignore();
}

// 鼠标移动时间处理
void Widget::mouseMoveEvent(QMouseEvent *event)
{
    int poss = countFlag(event->pos(),countRow(event->pos()));

    setCursorType(poss);
    if(isLeftPressed){
        QPoint ptemp=event->globalPos();
        ptemp=ptemp-pLast;
        // 移动窗口
        if(curPos == 22){
            ptemp=ptemp+pos();
            move(ptemp);
        }
        else{
            QRect wid=geometry();

            switch(curPos){
                case 11:wid.setTopLeft(wid.topLeft()+ptemp);break;          //左上角
                case 13:wid.setTopRight(wid.topRight()+ptemp);break;        //右上角
                case 31:wid.setBottomLeft(wid.bottomLeft()+ptemp);break;    //左下角
                case 33:wid.setBottomRight(wid.bottomRight()+ptemp);break;  //右下角
                case 12:wid.setTop(wid.top()+ptemp.y());break;              //中上角
                case 21:wid.setLeft(wid.left()+ptemp.x());break;            //中左角
                case 23:wid.setRight(wid.right()+ptemp.x());break;          //中右角
                case 32:wid.setBottom(wid.bottom()+ptemp.y());break;        //中下角
            }
            setGeometry(wid);
        }
        // 更新位置
        pLast=event->globalPos();
    }
    event->ignore();
}

// 计算鼠标在哪一列和哪一行
int Widget::countFlag(QPoint p,int row)
{
    if(p.y()< MARGIN)
        return 10+row;
    else if(p.y()>this->height() - MARGIN)
        return 30+row;
    else
        return 20+row;
}

// 根据鼠标所在位置改变鼠标指针形状
void Widget::setCursorType(int flag)
{
    Qt::CursorShape cursor = Qt::ArrowCursor;
    switch(flag){
        case 11:
        case 33:
        cursor = Qt::SizeFDiagCursor;break;
        case 13:
        case 31:
        cursor = Qt::SizeBDiagCursor;break;
        case 21:
        case 23:
        cursor = Qt::SizeHorCursor;break;
        case 12:
        case 32:
        cursor = Qt::SizeVerCursor;break;
        case 22:
        cursor = Qt::ArrowCursor;break;
        default:
        // 恢复鼠标指针形状
        //QApplication::restoreOverrideCursor();
        break;
    }
    setCursor(cursor);
}

// 计算在哪一列
int Widget::countRow(QPoint p)
{
    return (p.x()<MARGIN)?1:(p.x()>(this->width()-MARGIN)?3:2);
}

//-----------------------------------------------------------
// 最大小、关闭按钮槽函数
//-----------------------------------------------------------
void Widget::on_minButton_clicked()
{
    this->setWindowState(Qt::WindowMinimized);
}

void Widget::on_maxButton_clicked()
{
    if(windowState() == Qt::WindowMaximized){
        this->setWindowState(Qt::WindowNoState);
    }
    else this->setWindowState(Qt::WindowMaximized);
}

void Widget::on_closeButton_clicked()
{
    //this->close();
    exit(0);
}

//-----------------------------------------------------------
//其他槽函数
//-----------------------------------------------------------
void Widget::on_ComboBoxAdapter_currentIndexChanged(const QString &arg1)
{   
    //ui->ComboBoxAdapter->setEnabled(false);
}

void Widget::on_pushButtonOpenAdapter_clicked()
{
    ui->pushButtonOpenAdapter->setEnabled(false);
    ui->labelStatus->setText(tr("获取本机网络信息中"));
    QString devStr = ui->ComboBoxAdapter->currentText();    

    QByteArray devByteArray = devStr.toUtf8();
    const char *devName = devByteArray.data();
    // 1打开适配器
    pcap->openLiveDev(devName);
    // 2获取本机ip和netmask
    pcap->setHostInfo(devName);
    // 3线程获取本机MAC
    pcap->getSelfMac();
    // 开启流量监控线程
    pcap->trafficStatistic(devName);
}

void Widget::getSelfMacFinishedSlot(QString mac)
{    
    ui->pushButtonStartScan->setEnabled(true);
    ui->labelStatus->setText(tr("获取本机信息完毕"));
    ui->lineEditIPStart->setText(pcap->getHostIp());
    ui->lineEditIPEnd->setText(pcap->getHostIp());
    pcap->setPcapStatus(true);

    ui->labelHostIP->setText(pcap->getHostIp());
    ui->labelHostNetmask->setText(pcap->getHostNetmask());
    ui->labelHostMac->setText(mac);
}

void Widget::scanHostFinishedSlot()
{
    ui->labelStatus->setText(tr("扫描主机结束"));
    int hostNum = ui->tableWidget->rowCount();
    ui->labelHostNum->setText(QString::number(hostNum));
    // 获取gateway MAC
    QString gatewayMac = getGatewayMacFromTabWidget();
    ui->labelGatewayMac->setText(gatewayMac);
    pcap->setGatewayMac(gatewayMac);

    // 在这里获取个ip的主机名，因为WSAStartup()，一个个去获取，每个耗费几秒钟
    // ，但是一次性获取总共只需要耗费几秒钟这个问题，所以，这里获取完ip和mac信息后，
    // 再一次性获取所有的主机名，但是在UI上获取数据不同步了，还没找到好的解决办法。
    QVector<QString> allHostIp;
    for(int i = 0; i < ui->tableWidget->rowCount(); ++i){
        QTableWidgetItem *item =  ui->tableWidget->item(i,0);
        allHostIp.append(item->text());
    }

    GetAllHostName * getallhostnameThread = new GetAllHostName(allHostIp);
    connect(getallhostnameThread,SIGNAL(getHostnameByIpStrUpdateSig(QPair<QString,QString>)),this,SLOT(getHostnameByIpStrUpdateSlot(QPair<QString,QString>)));

    getallhostnameThread->start();
}

void Widget::scanCurrentIpSlot(QString cuttentIp)
{
    ui->labelStatus->setText(cuttentIp);
}

void Widget::scanGetHostInfoSlot(QPair< QString,QString >info)
{
    // 添加进table中，并处理重复ip
    // qDebug () << info.first << " " << info.second;
    addANewHost(info);
}

void Widget::on_pushButtonStartScan_clicked()
{
    QString ipStart = ui->lineEditIPStart->text();
    QString ipEnd = ui->lineEditIPEnd->text();

    QRegExp regExp("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
    int pos = regExp.indexIn(ipStart);
    if(pos == -1){
        ui->labelStatus->setText("起始IP填写不规范");
        return ;
    }
    pos = regExp.indexIn(ipEnd);
    if(pos == -1){
        ui->labelStatus->setText("结束IP填写不规范");
        return ;
    }

    bool isValid =  pcap->ipStart2EndIsValid(ipStart,ipEnd);
    if(!isValid){
        ui->labelStatus->setText("起始结束IP填写大小错误");
        return ;
    }

    ui->labelStatus->setText("开始扫描...");

    // 清除上一次扫描的主机,不能用clear和clearcontent?
    if(ui->tableWidget->rowCount() != 0){
        for(int i = 0; i < ui->tableWidget->rowCount();){
            if(ui->tableWidget->item(i,3)->text() == tr("ARP攻击中")){
                ++i;
                continue;
            }
            ui->tableWidget->removeRow(i);
            ui->tableWidget->update();
        }
    }

    pcap->scanLANHost(ipStart,ipEnd);
}

void Widget::tablItemDoubleClickedSlot(QTableWidgetItem *item)
{
    int row = item->row();

    QTableWidgetItem *tempItem = ui->tableWidget->item(row,3);

    if(tempItem->text() == tr("ARP攻击中")){
        // 停止攻击
        ui->tableWidget->item(row,3)->setText(tr("正常"));
        ui->tableWidget->item(row,3)->setTextColor(QColor(0,0,0));
        // 停止攻击线程
        tempItem = ui->tableWidget->item(row,0);
        QString cheatIp = tempItem->text();
        pcap->quitArpCheatThread(cheatIp);
    }
    else {
        tempItem = ui->tableWidget->item(row,0);
        QString cheatIp = tempItem->text();
        tempItem = ui->tableWidget->item(row,2);
        QString cheatMac = tempItem->text();
        tempItem = ui->tableWidget->item(row,3);
        tempItem->setText(tr("ARP攻击中"));
        tempItem->setTextColor(QColor(255,0,0));
        // 开始发送欺骗包
        QString gatewayMac = getGatewayMacFromTabWidget();
        pcap->arpCheatHost(cheatIp,cheatMac,gatewayMac);
    }
}

void Widget::itemEnteredHover(QTableWidgetItem *item)
{
    //qDebug()<< "hover item";
    //item->toolTip();
}

void Widget::trafficStatisticNetSpeedSlot(QString netSpeed)
{
    QString downloadSpeedStr = netSpeed + "KB/S";
    ui->labelDownload->setText(downloadSpeedStr);
}

void Widget::filterUpdateDataSlot(QString data)
{
    int row = ui->listWidget->count();
    QListWidgetItem *newItem = new QListWidgetItem;
    newItem->setText(data);
    ui->listWidget->insertItem(row, newItem);
}

void Widget::filterStatusSlot(int num,QString msg)
{
    //qDebug()<< num << " " << msg;
    if(num < 0)pcap->stopFilter();
    ui->labelStatus->setText(msg);
}

void Widget::on_pushButtonApplyFilter_clicked()
{
    if(!pcap->getPcapStatus()){
        ui->labelStatus->setText(tr("适配器未准备就绪"));
        return ;
    }

    // 过滤关键字包tcp udp arp icmp
    QString filter = ui->LineEditFilter->text();
    // 适配器
    QString devStr = ui->ComboBoxAdapter->currentText();
    QByteArray devByteArray = devStr.toUtf8();
    const char *devName = devByteArray.data();

    if(pcap->getFilterThreadStatus()){
        pcap->stopFilter();

    }
    // 清空列表
    if(ui->listWidget->count()){
        ui->listWidget->clear();
    }
    pcap->applyFilter(devName,filter);    
}

void Widget::on_pushButtonStopFilter_clicked()
{   
    if(pcap->getFilterThreadStatus()){
        pcap->stopFilter();
        // 清空列表
        // ui->listWidget->clear();
    }
}

void Widget::on_pushButtonApplyPing_clicked()
{
    QString pingIp = ui->LineEditPing->text();
    QString pingNum = ui->lineEditPingNum->text();
    if(ui->listWidgetPing->count()){
        ui->listWidgetPing->clear();
    }
    pcap->applyPing(pingIp,pingNum.toInt());
}

// 获取主机名线程更新数据槽函数
void Widget::getHostnameByIpStrUpdateSlot(QPair<QString,QString> info)
{
    hostnameBuffer.enqueue(info);
}

// getHostnameTimer 定时取主机名缓冲区队列中数据
void Widget::getHostnameFromQQueueBufferSlot()
{
    if(!hostnameBuffer.isEmpty()){
        QPair<QString,QString> info = hostnameBuffer.dequeue();
        updateHostname(info.first,info.second);
    }
}

// ping 更新echo
void Widget::pingUpdateEchoSlot(QString echo)
{
    ui->listWidgetPing->addItem(echo);
}

void Widget::on_pushButtonPortScan_clicked()
{
    if(!pcap->getPcapStatus()){
        ui->labelStatus->setText(tr("适配器未准备就绪"));
        return ;
    }

    QString scanIp = ui->LineEditPortScanIp->text();
    QString scanMac;
    int row = ui->tableWidget->rowCount();

    for(int i = 0;i < row; ++i){
        QString strText = ui->tableWidget->item(i,0)->text();
        if(scanIp == strText){
           scanMac = ui->tableWidget->item(i,2)->text();
        }
    }

    QString scanStartPort = ui->lineEditStartPort->text();
    QString scanEndPort = ui->lineEditEndPort->text();

    QString devStr = ui->ComboBoxAdapter->currentText();
    QByteArray devByteArray = devStr.toUtf8();
    const char *devName = devByteArray.data();

    // 清除上一次的结果
    if(ui->listWidgetPortScan->count() > 0){
        ui->listWidgetPortScan->clear();
    }

    pcap->applyPortScan(devName,scanIp,scanMac,scanStartPort.toUShort(),scanEndPort.toUShort());
    //pcap->applyPortScan(scanIp,scanMac,scanStartPort.toUShort(),scanEndPort.toUShort());
    ui->labelStatus->setText(tr("开始端口扫描"));
}

// 端口扫描结束
void Widget::portScanIsFinishedSlot()
{
    ui->labelStatus->setText(tr("端口扫描结束"));
}

// 端口扫描获取SYN-ACK更新
void Widget::portScanRecvUpdataSlot(QString msg)
{
    ui->listWidgetPortScan->addItem(msg);
}

void Widget::on_setButton_clicked()
{
    aboutDialog->show();
}
