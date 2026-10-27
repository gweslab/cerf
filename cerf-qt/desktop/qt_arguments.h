#pragma once

#include <string>
#include <vector>

class QtArguments {
public:
    QtArguments(int argc, char** argv);
    QtArguments(const QtArguments&)            = delete;
    QtArguments& operator=(const QtArguments&) = delete;

    int&   QtCount() { return qt_count_; }
    char** QtValues() { return qt_.data(); }

    void   KeepWhatQtLeft();
    int    Count() const { return static_cast<int>(kept_.size()) - 1; }
    char** Values() { return kept_.data(); }

private:
    bool QtKept(const char* argument) const;

    std::vector<std::string> utf8_;
    std::vector<char*>       original_;
    std::vector<char*>       qt_;
    std::vector<char*>       kept_;
    int                      qt_count_ = 0;
};
