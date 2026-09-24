#pragma once

#include "../../core/service.h"
#include "pcmcia_card.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

/* The set of PC Card types CERF can insert into any slot at runtime.
   Slot "Insert card" menus list Entries(); the chosen id goes through
   Create(). */
class PcmciaCardCatalog : public Service {
public:
    using Service::Service;

    using CardInserter = std::function<void(std::unique_ptr<PcmciaCard>)>;

    struct Entry {
        std::string  id;
        std::wstring display_name;
        /* When set, the slot renders this entry as a submenu built here;
           each action builds a card and hands it to the inserter. Used by
           CompactFlash (Choose image / default / Generate actions). */
        std::function<std::vector<WidgetMenuItem>(CardInserter)> insert_submenu;
    };

    void OnReady() override;

    const std::vector<Entry>& Entries() const { return entries_; }
    std::unique_ptr<PcmciaCard> Create(const std::string& id,
                                       const std::wstring& binding = L"");
    std::unique_ptr<PcmciaCard> TryCreate(const std::string& id,
                                          const std::wstring& binding = L"");

private:
    std::vector<Entry> entries_;
};
