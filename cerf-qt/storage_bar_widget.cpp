#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_storage.h>

#include <memory>
#include <string>

namespace cerffrontend {

namespace {

class StorageBarWidget final : public BarWidget {
public:
    explicit StorageBarWidget(cerfcore::MachineStorage& storage) : storage_(storage) {}

    std::string Name() const override { return storage_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Storage; }

    BarIcon Icon() const override {
        if (storage_.Medium() == cerfcore::StorageMedium::kHardDisk) return HardDiskIcon{};
        return ChipIcon{};
    }

    std::string Tooltip() const override {
        switch (storage_.Medium()) {
            case cerfcore::StorageMedium::kNorFlash:  return "NOR Flash - " + Name();
            case cerfcore::StorageMedium::kNandFlash: return "NAND Flash storage (" + storage_.ImagePath() + ")";
            case cerfcore::StorageMedium::kHardDisk:  return Name();
        }
        return Name();
    }

    std::vector<MenuItem> Menu() override { return {MenuItem::Info(Tooltip())}; }

    uint64_t RxCount() const override { return storage_.RxCount(); }
    uint64_t TxCount() const override { return storage_.TxCount(); }

private:
    cerfcore::MachineStorage& storage_;
};

class StorageBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* storage = dynamic_cast<cerfcore::MachineStorage*>(&object);
        if (!storage) return nullptr;
        return std::make_unique<StorageBarWidget>(*storage);
    }
};

}

REGISTER_SERVICE(StorageBarWidgetSource);

}
