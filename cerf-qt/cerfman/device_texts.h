#pragma once

#include "device_bundle.h"

#include <cerfcore/core/service.h>

#include <QString>
#include <QStringList>

#include <tuple>
#include <vector>

using GroupKey = std::tuple<int, QString>;
using SortKey  = std::tuple<QString, bool, QString, bool, int, int, bool, int, QString>;

class DeviceTexts : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    QString    GroupName(const DeviceBundle& device) const;
    QString    DeviceLabel(const DeviceBundle& device) const;
    QString    OsLabel(const DeviceBundle& device) const;
    QString    OsTitle(const DeviceBundle& device) const;
    QString    OsNotes(const DeviceBundle& device) const;
    QString    CardTitle(const DeviceBundle& device) const;
    QString    CardSubtitle(const DeviceBundle& device) const;
    QString    PanelDetail(const DeviceBundle& device) const;
    QStringList SearchFields(const DeviceBundle& device) const;
    GroupKey   BoardGroupKey(const DeviceBundle& device) const;
    GroupKey   DeviceGroupKey(const DeviceBundle& device) const;
    SortKey    DeviceSortKey(const DeviceBundle& device) const;
    void       SortForCards(std::vector<DeviceBundle>& devices) const;

private:
    QString OsCeVersion(const DeviceBundle& device) const;
    int     DeviceYear(const DeviceBundle& device) const;
    int     BoardTier(const DeviceBundle& device) const;
};
