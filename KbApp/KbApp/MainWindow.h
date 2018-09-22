#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "ObjectsStorage.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_EnableBeeperButton_clicked();

    void on_FreqSlider_valueChanged(int value);

    void on_FreqEdit_editingFinished();

    void on_ReadPortButton_clicked();

    void on_WritePortButton_clicked();

    void on_CliButton_clicked();

    void on_StiButton_clicked();

    void on_HltButton_clicked();

    void on_RdmsrButton_clicked();

    void on_WrmsrButton_clicked();

    void on_RdpmcButton_clicked();

private:
    Ui::MainWindow *ui;
    ObjectsStorage objectsStorage;
    bool isHex(const QString& string);
    int getInt(const QString& string);
    long long getInt64(const QString& string);
    unsigned int getUInt(const QString& string);
    unsigned long long getUInt64(const QString& string);
};

#endif // MAINWINDOW_H
