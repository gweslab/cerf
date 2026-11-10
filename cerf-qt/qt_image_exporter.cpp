#include "image_exporter.h"

#include "qt_ui_thread_calls.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_file.h>

#include <QBuffer>
#include <QByteArray>
#include <QClipboard>
#include <QGuiApplication>
#include <QImage>

#include <string_view>

namespace {

QImage Wrap(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h) {
    return QImage(reinterpret_cast<const uchar*>(pixels.data()), static_cast<int>(w),
                  static_cast<int>(h), static_cast<qsizetype>(w) * 4, QImage::Format_RGB32);
}

class QtImageExporter : public cerffrontend::ImageExporter {
public:
    using cerffrontend::ImageExporter::ImageExporter;

    bool EncodePng(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h, std::vector<uint8_t>& png) override {
        QByteArray encoded;
        QBuffer    buffer(&encoded);
        buffer.open(QIODevice::WriteOnly);
        if (!Wrap(pixels, w, h).save(&buffer, "PNG")) {
            LOG(Caution, "QtImageExporter: %ux%u image not encoded as PNG\n", w, h);
            return false;
        }
        png.assign(encoded.cbegin(), encoded.cend());
        return true;
    }

    bool WritePng(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                  const std::string& path) override {
        std::vector<uint8_t> png;
        return EncodePng(pixels, w, h, png) && WriteEncodedPng(png, path);
    }

    bool WriteEncodedPng(const std::vector<uint8_t>& png, const std::string& path) override {
        uint32_t error = 0;
        if (cerfcore::host_platform::ReplaceHostFileContents(
                path, std::string_view(reinterpret_cast<const char*>(png.data()), png.size()), false, error))
            return true;
        LOG(Caution, "QtImageExporter: PNG %s not written: %s\n", path.c_str(),
            cerfcore::host_platform::ErrorText(error).c_str());
        return false;
    }

    bool CopyToClipboard(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h) override {
        const QImage copy = Wrap(pixels, w, h).copy();
        return emu_.Get<QtUiThreadCalls>().Run([copy] { QGuiApplication::clipboard()->setImage(copy); });
    }
};

}

REGISTER_SERVICE_AS(QtImageExporter, cerffrontend::ImageExporter);
