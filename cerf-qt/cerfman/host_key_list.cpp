#include "host_key_list.h"

#include "../host_key_binding.h"

#include <algorithm>
#include <utility>

QVariantList HostKeyVariantList(const std::vector<uint8_t>& vks) {
    QVariantList out;
    for (uint8_t vk : vks) out.append(int(vk));
    return out;
}

std::vector<uint8_t> HostKeyVks(const QVariantList& vks) {
    std::vector<uint8_t> out;
    for (const QVariant& value : vks) {
        const int vk = value.toInt();
        if (vk >= 1 && vk <= 255 && std::find(out.begin(), out.end(), uint8_t(vk)) == out.end())
            out.push_back(uint8_t(vk));
    }
    return cerffrontend::HostKeyBinding::OrDefault(std::move(out));
}
