#include "widget.h"
#include "ui_widget.h"
#include <QMouseEvent>
#include <QDebug>
#include "NoFocusDelegate.h"


Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);   
    mouseAndWinInit();
    tabWidgetPanelInit();
    tabViewInit();
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

// TabView初始化
void Widget::tabViewInit()
{
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->horizontalHeader()->setFixedHeight(35);
    QStringList header;
    header <<tr("IP地址")<<tr("机器名")<<tr("上行带宽(KB/S)") << "下行带宽(KB/S)"
           << tr("MAC地址") << tr("网卡描述") << tr("日流量");
    ui->tableWidget->setHorizontalHeaderLabels(header);
    QFont font = ui->tableWidget->horizontalHeader()->font();
    font.setBold(true);
    ui->tableWidget->horizontalHeader()->setFont(font);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->setStyleSheet("selection-background-color:lightblue;");
    //ui->tableWidget->horizontalHeader()->setStyleSheet("QHeaderView::section{background:greenyellow;}");
    ui->tableWidget->horizontalHeader()->setHighlightSections(false);
    ui->tableWidget->setFrameShape(QFrame::NoFrame);
    ui->tableWidget->verticalHeader()->hide();
    //ui->tableWidget->horizontalHeader()->resizeSection(0,150);
    //ui->tableWidget->horizontalHeader()->resizeSection(1,80);
    //ui->tableWidget->horizontalHeader()->resizeSection(2,160);
    //ui->tableWidget->horizontalHeader()->resizeSection(3,160);
    ui->tableWidget->setItemDelegate(new NoFocusDelegate());
    ui->tableWidget->setMouseTracking(true);
}

//-----------------------------------------------------------
//鼠标和窗口的初始化
//-----------------------------------------------------------
void Widget::mouseAndWinInit()
{
    //获取最小化、关闭按钮图标
    QPixmap minPix  = style()->standardPixmap(QStyle::SP_TitleBarMinButton);
    QPixmap closePix = style()->standardPixmap(QStyle::SP_TitleBarCloseButton);
    QPixmap maxPix = style()->standardPixmap(QStyle::SP_TitleBarMaxButton);
    QPixmap setPix = style()->standardPixmap(QStyle::SP_TitleBarUnshadeButton);

    //设置最小化、关闭按钮图标
    ui->minButton->setIcon(minPix);
    ui->maxButton->setIcon(maxPix);
    ui->closeButton->setIcon(closePix);
    ui->setButton->setIcon(setPix);

    ui->minButton->setToolTip(tr("最小化"));
    ui->maxButton->setToolTip(tr("最大化"));
    ui->closeButton->setToolTip(tr("关闭"));
    ui->setButton->setToolTip(tr("查看在线主机信息"));
    //窗口鼠标拖动相关
    //设置主窗口无边框
    this->setWindowFlags(Qt::FramelessWindowHint);
    //设置在不按鼠标的情况下也触发鼠标移动事件
    this->setMouseTracking(true);
    //鼠标左键按下标记
    isLeftPressed = false;
    //标记鼠标左击时的位置
    curPos = 0;
}

//-----------------------------------------------------------
//窗口移动、缩放处理部分
//-----------------------------------------------------------
//鼠标按下事件
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

//鼠标释放事件
void Widget::mouseReleaseEvent(QMouseEvent *event)
{
    if(isLeftPressed)
        isLeftPressed=false;
    //恢复鼠标指针形状
    QApplication::restoreOverrideCursor();
    event->ignore();
}

//鼠标双击事件
void Widget::mouseDoubleClickEvent(QMouseEvent *event)
{
    if(event->button()==Qt::LeftButton){
        if(windowState()!=Qt::WindowFullScreen)
            //双击窗口全屏
            setWindowState(Qt::WindowFullScreen);
        //恢复正常模式
        else setWindowState(Qt::WindowNoState);
    }
    event->ignore();
}

//鼠标移动时间处理
void Widget::mouseMoveEvent(QMouseEvent *event)
{
    int poss = countFlag(event->pos(),countRow(event->pos()));

    setCursorType(poss);
    if(isLeftPressed){
        QPoint ptemp=event->globalPos();
        ptemp=ptemp-pLast;
        //移动窗口
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
        //更新位置
        pLast=event->globalPos();
    }
    event->ignore();
}

//计算鼠标在哪一列和哪一行
int Widget::countFlag(QPoint p,int row)
{
    if(p.y()< MARGIN)
        return 10+row;
    else if(p.y()>this->height() - MARGIN)
        return 30+row;
    else
        return 20+row;
}

//根据鼠标所在位置改变鼠标指针形状
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
        //恢复鼠标指针形状
        //QApplication::restoreOverrideCursor();
        break;
    }
    setCursor(cursor);
}

//计算在哪一列
int Widget::countRow(QPoint p)
{
    return (p.x()<MARGIN)?1:(p.x()>(this->width()-MARGIN)?3:2);
}

//-----------------------------------------------------------
//最大小、关闭按钮槽函数
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
    this->close();
}

//-----------------------------------------------------------
//其他槽函数
//-----------------------------------------------------------
void Widget::on_adapterComboBox_currentIndexChanged(const QString &arg1)
{
    qDebug()<< arg1;

    ui->adapterComboBox->setEnabled(false);
}
