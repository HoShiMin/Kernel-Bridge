#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <qmessagebox.h>
#include <qgraphicseffect.h>
#include <qdesktopwidget.h>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow), objectsStorage()
{
    ui->setupUi(this);
    BOOL Status = KbLoader::KbLoadAsFilter(L"C:\\Temp\\Kernel-Bridge\\Kernel-Bridge.sys", L"260000");
    if (!Status) {
        QMessageBox msg;
        msg.critical(ui->MainForm, "Error!", "Unable to load driver!\r\nEnsure to run it as Administrator!");
    }
}

MainWindow::~MainWindow()
{
    KbLoader::KbUnload();
    delete ui;
}

bool MainWindow::isHex(const QString& string) {
    return string.startsWith("0x") || string.startsWith("$");
}

int MainWindow::getInt(const QString& string) {
    bool Status = false;
    return isHex(string) ? string.toInt(&Status, 16) : string.toInt();
}

long long MainWindow::getInt64(const QString& string) {
    bool Status = false;
    return isHex(string) ? string.toLongLong(&Status, 16) : string.toLongLong();
}

unsigned int MainWindow::getUInt(const QString& string) {
    bool Status = false;
    return isHex(string) ? string.toUInt(&Status, 16) : string.toUInt();
}

unsigned long long MainWindow::getUInt64(const QString& string) {
    bool Status = false;
    return isHex(string) ? string.toULongLong(&Status, 16) : string.toULongLong();
}

void MainWindow::on_EnableBeeperButton_clicked()
{
    static BOOL Enabled = FALSE;
    Enabled = !Enabled;

    if (Enabled) {
        IO::Beeper::KbSetBeeperRegime();
        unsigned short Frequency = ui->FreqEdit->text().toUShort();
        if (Frequency <= 0) Frequency = 1;
        if (Frequency > 20000) Frequency = 20000;
        IO::Beeper::KbSetBeeperFrequency(Frequency);
        IO::Beeper::KbStartBeeper();
        ui->EnableBeeperButton->setText("Disable beeper");
    } else {
        IO::Beeper::KbStopBeeper();
        ui->EnableBeeperButton->setText("Enable beeper");
    }
}

void MainWindow::on_FreqSlider_valueChanged(int value)
{
    ui->FreqEdit->setText(QString::number(value));
    ui->FreqEdit->editingFinished();
}

void MainWindow::on_FreqEdit_editingFinished()
{
    unsigned short Frequency = ui->FreqEdit->text().toUShort();
    if (Frequency <= 0) Frequency = 1;
    if (Frequency > 20000) Frequency = 20000;
    ui->FreqEdit->setText(QString::number(Frequency));
    IO::Beeper::KbSetBeeperFrequency(Frequency);
}

void MainWindow::on_ReadPortButton_clicked()
{
    unsigned int Value = 0;
    unsigned int PortNumber = getUInt(ui->PortNumberEdit->text());

    if (PortNumber > 255) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Port number must be in [0..255] interval!");
        return;
    }

    unsigned char CheckedPortNumber = static_cast<unsigned char>(PortNumber);

    BOOL Status = FALSE;
    if (ui->ByteRadioButton->isChecked()) {
        unsigned char CharValue = 0;
        Status = IO::RW::KbReadPortByte(CheckedPortNumber, &CharValue);
        Value = CharValue;
    } else if (ui->WordRadioButton->isChecked()) {
        unsigned short WordValue = 0;
        Status = IO::RW::KbReadPortWord(CheckedPortNumber, &WordValue);
        Value = WordValue;
    } else if (ui->DwordRadioButton->isChecked()) {
        unsigned long DwordValue = 0;
        Status = IO::RW::KbReadPortDword(CheckedPortNumber, &DwordValue);
        Value = DwordValue;
    }

    if (!Status) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Error in read port!");
    }

    ui->PortValueEdit->setText(QString::number(Value));
}

void MainWindow::on_WritePortButton_clicked()
{
    unsigned int Value = getUInt(ui->PortValueEdit->text());
    unsigned int PortNumber = getUInt(ui->PortNumberEdit->text());

    if (Value > 255 || PortNumber > 255) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Port number and value must be in [0..255] interval!");
        return;
    }

    unsigned char CheckedPortNumber = static_cast<unsigned char>(PortNumber);

    BOOL Status = FALSE;
    if (ui->ByteRadioButton->isChecked()) {
        Status = IO::RW::KbWritePortByte(CheckedPortNumber, static_cast<unsigned char>(Value));
    } else if (ui->WordRadioButton->isChecked()) {
        Status = IO::RW::KbWritePortWord(CheckedPortNumber, static_cast<unsigned short>(Value));
    } else if (ui->DwordRadioButton->isChecked()) {
        Status = IO::RW::KbWritePortDword(CheckedPortNumber, static_cast<unsigned long>(Value));
    }

    if (!Status) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Error in write port!");
    }
}

void MainWindow::on_CliButton_clicked()
{
    CPU::KbCli();
}

void MainWindow::on_StiButton_clicked()
{
    CPU::KbSti();
    static int counter = 0;
    counter++;
    ui->FreqEdit->setText(QString::number(counter));
}

void MainWindow::on_HltButton_clicked()
{
    CPU::KbHlt();
}

void MainWindow::on_RdmsrButton_clicked()
{
    unsigned int MsrIndex = getUInt(ui->MsrPmcIndexEdit->text());
    unsigned long long Value = 0;
    BOOL Status = FALSE;

    Status = CPU::KbReadMsr(MsrIndex, &Value);

    if (!Status) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Error in read MSR!");
        return;
    }

    ui->MsrPmcValueEdit->setText("0x" + QString::number(Value, 16).toUpper());
}

void MainWindow::on_WrmsrButton_clicked()
{
    unsigned int MsrIndex = getUInt(ui->MsrPmcIndexEdit->text());
    unsigned long long Value = getUInt64(ui->MsrPmcValueEdit->text());
    BOOL Status = FALSE;

    Status = CPU::KbWriteMsr(MsrIndex, Value);

    if (!Status) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Error in write MSR!");
        return;
    }
}

void MainWindow::on_RdpmcButton_clicked()
{
    unsigned int PmcIndex = getUInt(ui->MsrPmcIndexEdit->text());
    unsigned long long Value = 0;
    BOOL Status = FALSE;

    Status = CPU::KbReadPmc(PmcIndex, &Value);

    if (!Status) {
        QMessageBox msgBox;
        msgBox.critical(ui->MainForm, "Error!", "Error in read PMC!");
        return;
    }

    ui->MsrPmcValueEdit->setText("0x" + QString::number(Value, 16).toUpper());
}
