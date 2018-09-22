#include "MainWindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    KbLoader::KbLoadAsFilter(L"C:\\Temp\\Kernel-Bridge\\Kernel-Bridge.sys", L"260000");

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    int status = a.exec();

    KbLoader::KbUnload();
    return status;
}
