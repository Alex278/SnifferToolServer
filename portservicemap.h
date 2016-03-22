#ifndef PORTSERVICEMAP_H
#define PORTSERVICEMAP_H

#include <QString>
#include <QMap>

class PortServiceMap
{
private:
    QMap<unsigned short,QString> *portService;
    static PortServiceMap *portServiceMap;
public:
    PortServiceMap();

    // 它的唯一工作就是在析构函数中删除PortServiceMap的实例
//    class CGarbo
//    {
//        public:
//            ~CGarbo()
//            {
//                if(PortServiceMap::portServiceMap)
//                    delete PortServiceMap::portServiceMap;
//            }
//    };
//    static CGarbo Garbo;
public:
    QString getService(unsigned short port){
        return portService->value(port,"unknown");
    }
//    static PortServiceMap *getInstance(){
//        if(portServiceMap == NULL){
//            portServiceMap = new PortServiceMap();
//        }
//        return portServiceMap;
//    }
};

#endif // PORTSERVICEMAP_H
