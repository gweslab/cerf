#include <cerfcore/host/task_manager_view.h>

#include "qt_main_window.h"

#include "../qt_rgb_color.h"
#include "task_manager_model.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_task_manager_regs.h>

#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QResizeEvent>
#include <QTabBar>
#include <QTimer>
#include <QTreeWidget>

#include <algorithm>

namespace {

using Model = cerffrontend::TaskManagerModel;

constexpr int kTabWindows   = 0;
constexpr int kTabProcesses = 1;

QColor StatusColor(Model::StatusKind kind) {
    cerffrontend::Rgb c = Model::kInfoColor;
    if (kind == Model::StatusKind::kOk) c = Model::kOkColor;
    if (kind == Model::StatusKind::kFail) c = Model::kFailColor;
    return ToQColor(c);
}

class TaskManagerWidget : public QWidget {
public:
    TaskManagerWidget(cerfcore::CerfEmulator& emu, QWidget* owner)
        : QWidget(owner, Qt::Window), gate_(emu) {
        setWindowTitle(QStringLiteral("Guest Task Manager"));
        setAttribute(Qt::WA_DeleteOnClose);
        resize(Model::kClientW, Model::kClientH);
        setMinimumSize(Model::kMinTrackW, Model::kMinTrackH);

        tabs_ = new QTabBar(this);
        tabs_->setExpanding(false);
        tabs_->insertTab(kTabWindows, QStringLiteral("Windows"));
        tabs_->insertTab(kTabProcesses, QStringLiteral("Processes"));
        list_ = new QTreeWidget(this);
        list_->setRootIsDecorated(false);
        list_->setUniformRowHeights(true);
        list_->setSelectionMode(QAbstractItemView::SingleSelection);
        list_->setContextMenuPolicy(Qt::CustomContextMenu);
        list_->header()->setStretchLastSection(false);
        switch_ = new QPushButton(QStringLiteral("Switch to"), this);
        kill_   = new QPushButton(QStringLiteral("Kill"), this);
        label_  = new QLabel(QStringLiteral("Run:"), this);
        edit_   = new QLineEdit(this);
        edit_->setMaxLength(static_cast<int>(cerfcore::CerfVirt::kTmRunMaxWchars));
        run_    = new QPushButton(QStringLiteral("Run"), this);
        run_->setDefault(true);
        status_ = new QLabel(this);

        QObject::connect(tabs_, &QTabBar::currentChanged, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { OnTabChanged(emu.Get<Model>()); }));
        QObject::connect(switch_, &QPushButton::clicked, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { DoSwitchTo(emu.Get<Model>()); }));
        QObject::connect(kill_, &QPushButton::clicked, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { DoKill(emu.Get<Model>()); }));
        QObject::connect(run_, &QPushButton::clicked, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { DoRun(emu.Get<Model>()); }));
        QObject::connect(edit_, &QLineEdit::returnPressed, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { DoRun(emu.Get<Model>()); }));
        QObject::connect(list_, &QTreeWidget::customContextMenuRequested, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu, const QPoint& pos) {
                             ShowRowMenu(emu.Get<Model>(), pos);
                         }));
        QObject::connect(&timer_, &QTimer::timeout, this,
                         gate_.Bind([this](cerfcore::CerfEmulator& emu) { OnTick(emu.Get<Model>()); }));

        auto& model = emu.Get<Model>();
        model.Open();
        SetColumns(model);
        SyncStatus(model);
        timer_.start(static_cast<int>(Model::kRefreshMs));
    }

protected:
    void resizeEvent(QResizeEvent*) override { Layout(); }

private:
    void Layout() {
        const int m    = Model::kMargin;
        const int w    = width();
        const int h    = height();
        const int tabs_bottom = h - Model::kBottomBarH - m;
        const int tab_h       = tabs_->sizeHint().height();
        tabs_->setGeometry(m, m, w - 2 * m, tab_h);
        list_->setGeometry(m, m + tab_h, w - 2 * m, tabs_bottom - m - tab_h);

        const int row1 = h - Model::kBottomBarH;
        switch_->setGeometry(m, row1, Model::kBtnW, Model::kRowH);
        kill_->setGeometry(m + Model::kBtnW + 6, row1, Model::kBtnW, Model::kRowH);

        const int row2   = row1 + Model::kRowH + 8;
        const int edit_w = std::max(w - 2 * m - Model::kLabelW - Model::kBtnW - 12 -
                                        Model::kEditReserve,
                                    Model::kEditMinW);
        label_->setGeometry(m, row2 + 4, Model::kLabelW, Model::kRowH - 6);
        edit_->setGeometry(m + Model::kLabelW, row2, edit_w, Model::kRowH - 2);
        run_->setGeometry(m + Model::kLabelW + edit_w + 6, row2, Model::kBtnW, Model::kRowH);
        status_->setGeometry(m + Model::kLabelW + edit_w + Model::kBtnW + 12, row2 + 4,
                             Model::kStatusW, Model::kRowH - 6);
    }

    void SetColumns(Model& model) {
        const auto& cols = model.Columns();
        list_->clear();
        list_->setColumnCount(static_cast<int>(cols.size()));
        QStringList headers;
        for (const auto& c : cols) headers << QString::fromUtf8(c.title);
        list_->setHeaderLabels(headers);
        for (int i = 0; i < static_cast<int>(cols.size()); ++i)
            list_->setColumnWidth(i, cols[static_cast<size_t>(i)].width);
    }

    bool SelectedKey(uint32_t& key) const {
        const QList<QTreeWidgetItem*> sel = list_->selectedItems();
        if (sel.isEmpty()) return false;
        key = sel.front()->data(0, Qt::UserRole).toUInt();
        return true;
    }

    void Fill(Model& model) {
        uint32_t   sel     = 0;
        const bool had_sel = SelectedKey(sel);
        list_->clear();
        for (const auto& row : model.Rows()) {
            auto* item = new QTreeWidgetItem(list_);
            for (int c = 0; c < static_cast<int>(row.cells.size()); ++c)
                item->setText(c, QString::fromStdString(row.cells[static_cast<size_t>(c)]));
            item->setData(0, Qt::UserRole, row.key);
            if (had_sel && row.key == sel) item->setSelected(true);
        }
    }

    void SyncStatus(Model& model) {
        if (model.StatusSerial() == status_serial_) return;
        status_serial_ = model.StatusSerial();
        QPalette pal   = status_->palette();
        pal.setColor(QPalette::WindowText, StatusColor(model.Status()));
        status_->setPalette(pal);
        status_->setText(QString::fromStdString(model.StatusText()));
    }

    void OnTabChanged(Model& model) {
        model.SetMode(tabs_->currentIndex() == kTabProcesses ? Model::Mode::kProcesses
                                                             : Model::Mode::kWindows);
        SetColumns(model);
        SyncStatus(model);
    }

    void OnTick(Model& model) {
        if (model.Tick()) {
            Fill(model);
            setWindowTitle(QString::fromStdString(model.Title()));
        }
        SyncStatus(model);
    }

    void DoSwitchTo(Model& model) {
        uint32_t   key      = 0;
        const bool selected = SelectedKey(key);
        model.SwitchTo(selected, key);
        SyncStatus(model);
    }

    void DoKill(Model& model) {
        uint32_t   key      = 0;
        const bool selected = SelectedKey(key);
        model.Kill(selected, key);
        SyncStatus(model);
    }

    void DoRun(Model& model) {
        model.Run(edit_->text().toStdU16String());
        SyncStatus(model);
    }

    void ShowRowMenu(Model& model, const QPoint& pos) {
        if (QTreeWidgetItem* item = list_->itemAt(pos)) {
            list_->clearSelection();
            item->setSelected(true);
        }
        QMenu    menu;
        QAction* sw = menu.addAction(switch_->text());
        QAction* kl = menu.addAction(kill_->text());
        QAction* chosen = menu.exec(list_->viewport()->mapToGlobal(pos));
        if (chosen == sw) DoSwitchTo(model);
        if (chosen == kl) DoKill(model);
    }

    cerfcore::InstanceGate gate_;
    QTabBar*               tabs_   = nullptr;
    QTreeWidget*           list_   = nullptr;
    QPushButton*           switch_ = nullptr;
    QPushButton*           kill_   = nullptr;
    QLabel*                label_  = nullptr;
    QLineEdit*             edit_   = nullptr;
    QPushButton*           run_    = nullptr;
    QLabel*                status_ = nullptr;
    QTimer                 timer_;
    uint64_t               status_serial_ = 0;
};

class QtTaskManagerWindow : public cerfcore::TaskManagerView {
public:
    using cerfcore::TaskManagerView::TaskManagerView;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    void Show() override {
        if (window_) {
            if (window_->isMinimized()) window_->showNormal();
            window_->raise();
            window_->activateWindow();
            return;
        }
        window_ = new TaskManagerWidget(emu_, emu_.Get<QtMainWindow>().Window());
        window_->show();
    }

private:
    QPointer<TaskManagerWidget> window_;
};

}

REGISTER_SERVICE_AS(QtTaskManagerWindow, cerfcore::TaskManagerView);
