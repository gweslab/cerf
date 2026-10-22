#include "qt_shutdown_dialog.h"

#include "qt_main_window.h"
#include "qt_paint_resources.h"
#include "qt_painter.h"
#include "qt_theme.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerffrontend/dpi_scale.h>
#include <cerffrontend/link_opener.h>
#include <cerffrontend/shutdown_dialog_layout.h>
#include <cerffrontend/shutdown_prompt.h>

#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QElapsedTimer>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QTimer>

#include <functional>

REGISTER_SERVICE(QtShutdownDialog);

namespace {

using cerffrontend::ShutdownPrompt;
using cerffrontend::ShutdownPromptAction;
using Layout = cerffrontend::ShutdownDialogLayout;
using cerffrontend::kDefaultDpi;

QRect ToQRect(const cerffrontend::Rect& r) { return QRect(r.left, r.top, r.right - r.left, r.bottom - r.top); }

class PopupComboBox : public QComboBox {
public:
    using QComboBox::QComboBox;

    std::function<void()> on_popup;

    void showPopup() override {
        if (on_popup) on_popup();
        QComboBox::showPopup();
    }
};

class ShutdownDialogWidget : public QDialog {
public:
    ShutdownDialogWidget(cerfcore::CerfEmulator& emu, QWidget* owner, cerfcore::ShutdownTrigger trigger)
        : QDialog(owner),
          emu_(emu),
          layout_(kDefaultDpi, Layout::kBandH, Layout::kBandW,
                  Layout::ClientHeight(kDefaultDpi, Layout::kBandH)) {
        auto& prompt = emu_.Get<ShutdownPrompt>();
        setWindowTitle(QString::fromUtf8(prompt.Title()));
        setFixedSize(Layout::kBandW, Layout::ClientHeight(kDefaultDpi, Layout::kBandH));

        MakeLabel(QString::fromUtf8(prompt.Intro(trigger)), layout_.Intro());
        MakeLabel(QString::fromUtf8(prompt.Question()), layout_.Question());

        combo_ = new PopupComboBox(this);
        for (int i = 0; i < ShutdownPrompt::kActionCount; ++i)
            combo_->addItem(QString::fromUtf8(prompt.ActionLabel(static_cast<ShutdownPromptAction>(i))));
        combo_->setGeometry(ToQRect(layout_.Combo()));
        combo_->on_popup = [this] { Stop(); };

        save_ = new QCheckBox(QString::fromStdString(prompt.SaveLabel()), this);
        save_->setChecked(prompt.SaveByDefault());
        link_ = new QLabel(QStringLiteral("<a href=\"%1\">%2</a>")
                               .arg(QString::fromUtf8(prompt.SaveLinkUrl()),
                                    QString::fromUtf8(prompt.SaveLinkText())),
                           this);
        link_->setTextInteractionFlags(Qt::TextBrowserInteraction);
        tail_ = new QLabel(QString::fromUtf8(prompt.SaveTail()), this);
        LayoutSaveRow();

        remember_ = new QCheckBox(QString::fromUtf8(prompt.RememberLabel()), this);
        remember_->setGeometry(ToQRect(layout_.Remember()));
        desc_ = MakeLabel(QString(), layout_.Description());
        desc_->hide();

        auto* ok = new QPushButton(QStringLiteral("OK"), this);
        ok->setDefault(true);
        ok->setGeometry(ToQRect(layout_.Ok()));
        auto* cancel = new QPushButton(QString::fromUtf8(prompt.CancelLabel(trigger)), this);
        cancel->setGeometry(ToQRect(layout_.Cancel()));

        QObject::connect(combo_, &QComboBox::currentIndexChanged, this, [this] {
            Stop();
            Sync();
        });
        QObject::connect(save_, &QCheckBox::clicked, this, [this] { Stop(); });
        QObject::connect(remember_, &QCheckBox::clicked, this, [this] { Stop(); });
        QObject::connect(link_, &QLabel::linkActivated, this, [this](const QString& href) {
            Stop();
            emu_.Get<cerffrontend::LinkOpener>().Open(href.toStdString());
        });
        QObject::connect(ok, &QPushButton::clicked, this, [this] { Commit(); });
        QObject::connect(cancel, &QPushButton::clicked, this, [this] { reject(); });
        QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });

        counting_     = prompt.CountsDown(trigger);
        remaining_ms_ = static_cast<int>(ShutdownPrompt::kCountdownMs);
        if (counting_) {
            elapsed_.start();
            tick_.start(static_cast<int>(Layout::kTickMs));
        }
        combo_->setFocus();
    }

    cerfcore::ShutdownChoice Choice() const { return choice_; }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        auto&    res = emu_.Get<QtPaintResources>();
        p.drawImage(QRect(0, 0, Layout::kBandW, Layout::kBandH),
                    res.SvgImage("about_band", Layout::kBandW, Layout::kBandH));
        const QRect icon = ToQRect(layout_.Icon());
        p.drawImage(icon, res.SvgImage("suspend", icon.width(), icon.height()));
        if (!counting_ || combo_->currentIndex() != static_cast<int>(ShutdownPromptAction::Exit)) return;
        const QColor bg = palette().color(QPalette::Window);
        QtPainter    painter(emu_, p);
        layout_.PaintCountdown(painter,
                               cerffrontend::Rgb{static_cast<uint8_t>(bg.red()),
                                                 static_cast<uint8_t>(bg.green()),
                                                 static_cast<uint8_t>(bg.blue())},
                               emu_.Get<QtTheme>().IsDark(), remaining_ms_);
        painted_fill_w_ = layout_.BarFillWidth(remaining_ms_);
        painted_secs_   = Layout::RemainingSeconds(remaining_ms_);
    }

    void mousePressEvent(QMouseEvent* event) override {
        Stop();
        QDialog::mousePressEvent(event);
    }

private:
    QLabel* MakeLabel(const QString& text, const cerffrontend::Rect& r) {
        auto* label = new QLabel(text, this);
        label->setWordWrap(true);
        label->setAlignment(Qt::AlignLeft | Qt::AlignTop);
        label->setGeometry(ToQRect(r));
        return label;
    }

    void LayoutSaveRow() {
        const QRect row     = ToQRect(layout_.SaveRow());
        const int   check_w = save_->sizeHint().width();
        save_->setGeometry(row.left(), row.top(), check_w, row.height());
        const QSize link   = link_->sizeHint();
        const int   link_x = row.left() + check_w;
        const int   link_y = row.top() + (row.height() - link.height()) / 2;
        link_->setGeometry(link_x, link_y, link.width(), link.height());
        tail_->setGeometry(link_x + link.width(), link_y,
                           tail_->fontMetrics().horizontalAdvance(tail_->text()), link.height());
    }

    void Stop() {
        if (!counting_) return;
        counting_ = false;
        tick_.stop();
        update();
    }

    void Sync() {
        const auto action  = static_cast<ShutdownPromptAction>(combo_->currentIndex());
        const bool exiting = action == ShutdownPromptAction::Exit;
        save_->setVisible(exiting);
        link_->setVisible(exiting);
        tail_->setVisible(exiting);
        remember_->setVisible(exiting);
        desc_->setVisible(!exiting);
        if (!exiting)
            desc_->setText(QString::fromUtf8(emu_.Get<ShutdownPrompt>().ResetDescription(action)));
        update();
    }

    void Commit() {
        choice_ = emu_.Get<ShutdownPrompt>().Commit(
            static_cast<ShutdownPromptAction>(combo_->currentIndex()), save_->isChecked(),
            remember_->isChecked());
        accept();
    }

    void Tick() {
        const qint64 left = static_cast<qint64>(ShutdownPrompt::kCountdownMs) - elapsed_.elapsed();
        remaining_ms_     = left > 0 ? static_cast<int>(left) : 0;
        if (remaining_ms_ <= 0) {
            counting_ = false;
            tick_.stop();
            Commit();
            return;
        }
        if (layout_.BarFillWidth(remaining_ms_) != painted_fill_w_) update(ToQRect(layout_.Bar()));
        if (Layout::RemainingSeconds(remaining_ms_) != painted_secs_)
            update(ToQRect(layout_.Countdown()));
    }

    cerfcore::CerfEmulator& emu_;
    const Layout            layout_;
    PopupComboBox*          combo_    = nullptr;
    QCheckBox*              save_     = nullptr;
    QLabel*                 link_     = nullptr;
    QLabel*                 tail_     = nullptr;
    QCheckBox*              remember_ = nullptr;
    QLabel*                 desc_     = nullptr;
    QTimer                  tick_;
    QElapsedTimer           elapsed_;
    bool                    counting_       = false;
    int                     remaining_ms_   = 0;
    int                     painted_fill_w_ = -1;
    int                     painted_secs_   = -1;
    cerfcore::ShutdownChoice choice_        = cerfcore::ShutdownChoice::Cancel;
};

}

cerfcore::ShutdownChoice QtShutdownDialog::Show(cerfcore::ShutdownTrigger trigger) {
    if (open_ != nullptr) return cerfcore::ShutdownChoice::Cancel;
    ShutdownDialogWidget dialog(emu_, emu_.Get<QtMainWindow>().Window(), trigger);
    open_ = &dialog;
    dialog.exec();
    open_ = nullptr;
    return dialog.Choice();
}

void QtShutdownDialog::DismissAsCancel() {
    if (open_ != nullptr) open_->reject();
}
