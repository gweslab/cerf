#include "host_key_capture.h"

#include "../qt_key_position.h"
#include "host_key_list.h"

#include "../frontend_config.h"
#include "../host_key_binding.h"
#include "../host_key_label.h"
#include "../host_virtual_keys.h"

#include <QKeyEvent>

#include <algorithm>

namespace {

bool Contains(const std::vector<uint8_t>& list, uint8_t vk) {
    return std::find(list.begin(), list.end(), vk) != list.end();
}

}

HostKeyCapture::HostKeyCapture(QQuickItem* parent) : QQuickItem(parent) {
    setFlag(ItemAcceptsInputMethod, false);
    vks_       = cerffrontend::HostKeyBinding::OrDefault({});
    reset_vks_ = vks_;
}

QVariantList HostKeyCapture::Vks() const { return HostKeyVariantList(vks_); }

void HostKeyCapture::SetVks(const QVariantList& vks) {
    vks_ = HostKeyVks(vks);
    emit changed();
}

QVariantList HostKeyCapture::ResetVks() const { return HostKeyVariantList(reset_vks_); }

void HostKeyCapture::SetResetVks(const QVariantList& vks) {
    reset_vks_ = HostKeyVks(vks);
    emit changed();
}

QString HostKeyCapture::Label() const {
    if (capturing_ && pending_.empty()) return QStringLiteral("Press the new host key...");
    return QString::fromStdString(cerffrontend::HostKeyComboLabel(capturing_ ? pending_ : vks_));
}

void HostKeyCapture::Begin() {
    if (capturing_) {
        End(false);
        return;
    }
    capturing_ = true;
    pending_.clear();
    held_.clear();
    forceActiveFocus();
    emit changed();
}

void HostKeyCapture::Reset() {
    End(false);
    vks_ = reset_vks_;
    emit changed();
}

void HostKeyCapture::End(bool commit) {
    if (!capturing_) return;
    if (commit && !pending_.empty() &&
        !(pending_.size() == 1 && pending_.front() == cerffrontend::kVkEscape))
        vks_ = pending_;
    capturing_ = false;
    pending_.clear();
    held_.clear();
    emit changed();
}

void HostKeyCapture::keyPressEvent(QKeyEvent* event) {
    if (!capturing_) {
        event->ignore();
        return;
    }
    event->accept();
    if (event->isAutoRepeat()) return;
    QtHostKey key;
    uint32_t  native = 0;
    if (HostKeyPosition(event, key, native) != KeyPositionResult::kMapped) return;
    const uint8_t vk = key.sided_vk;
    if (!Contains(held_, vk)) held_.push_back(vk);
    if (!Contains(pending_, vk) && pending_.size() < cerffrontend::FrontendConfig::kMaxHostKeyLength) {
        pending_.push_back(vk);
        emit changed();
    }
}

void HostKeyCapture::keyReleaseEvent(QKeyEvent* event) {
    if (!capturing_) {
        event->ignore();
        return;
    }
    event->accept();
    if (event->isAutoRepeat()) return;
    QtHostKey key;
    uint32_t  native = 0;
    if (HostKeyPosition(event, key, native) == KeyPositionResult::kMapped)
        held_.erase(std::remove(held_.begin(), held_.end(), key.sided_vk), held_.end());
    if (held_.empty()) End(true);
}

void HostKeyCapture::focusOutEvent(QFocusEvent* event) {
    End(false);
    QQuickItem::focusOutEvent(event);
}
