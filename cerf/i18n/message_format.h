#pragma once

#include <initializer_list>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace cerf::i18n {

using MessageArgument = std::pair<std::string_view, std::string>;

std::set<std::string> MessageParameters(std::string_view message);
std::string RenderMessage(std::string_view message,
                          std::initializer_list<MessageArgument> arguments);
bool IsLanguageCode(std::string_view code);

}
