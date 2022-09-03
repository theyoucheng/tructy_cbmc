/*
 * Copyright 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TLOG_TAG "confirmationui"

#include "trusty_confirmation_ui.h"
#include "trusty_operation.h"

#include "device_parameters.h"

#include <interface/secure_fb/secure_fb.h>
#include <inttypes.h>
#include <layouts/layout.h>
#include <stdio.h>
#include <teeui/error.h>
#include <teeui/localization/ConfirmationUITranslations.h>
#include <teeui/utils.h>
#include <trusty_log.h>

using teeui::ResponseCode;

static constexpr const teeui::Color kColorEnabled = 0xff242120;
static constexpr const teeui::Color kColorDisabled = 0xffbdbdbd;
static constexpr const teeui::Color kColorEnabledInv = 0xffdedede;
static constexpr const teeui::Color kColorDisabledInv = 0xff424242;
static constexpr const teeui::Color kColorBackground = 0xffffffff;
static constexpr const teeui::Color kColorBackgroundInv = 0xff000000;
static constexpr const teeui::Color kColorShieldInv = 0xfff69d66;
static constexpr const teeui::Color kColorShield = 0xffe8731a;
static constexpr const teeui::Color kColorHintInv = 0xffa6a09a;
static constexpr const teeui::Color kColorHint = 0xff68635f;
static constexpr const teeui::Color kColorButton = 0xffe8731a;
static constexpr const teeui::Color kColorButtonInv = 0xfff69d66;

template <typename Label, typename Layout>
static teeui::Error updateString(Layout* layout) {
    using namespace teeui;
    const char* str;
    auto& label = std::get<Label>(*layout);

    str = localization::lookup(TranslationId(label.textId()));
    if (str == nullptr) {
        TLOGW("Given translation_id %" PRIu64 " not found", label.textId());
        return Error::Localization;
    }
    label.setText({str, str + strlen(str)});
    return Error::OK;
}

template <typename Context>
static void updateColorScheme(Context* ctx, bool inverted) {
    using namespace teeui;
    if (inverted) {
        ctx->template setParam<ShieldColor>(kColorShieldInv);
        ctx->template setParam<ColorText>(kColorBackground);
        ctx->template setParam<ColorBG>(kColorBackgroundInv);
        ctx->template setParam<ColorButton>(kColorButtonInv);
        ctx->template setParam<ColorButtonBG>(kColorEnabled);
        ctx->template setParam<ColorTextHint>(kColorHintInv);
    } else {
        ctx->template setParam<ShieldColor>(kColorShield);
        ctx->template setParam<ColorText>(kColorEnabled);
        ctx->template setParam<ColorBG>(kColorBackground);
        ctx->template setParam<ColorButton>(kColorButton);
        ctx->template setParam<ColorButtonBG>(kColorBackground);
        ctx->template setParam<ColorTextHint>(kColorHint);
    }
    return;
}

static teeui::Color alfaCombineChannel(uint32_t shift,
                                       double alfa,
                                       teeui::Color a,
                                       teeui::Color b) {
    a >>= shift;
    a &= 0xff;
    b >>= shift;
    b &= 0xff;
    double acc = alfa * a + (1 - alfa) * b;
    if (acc <= 0)
        return 0;
    uint32_t result = acc;
    if (result > 255)
        return 255 << shift;
    return result << shift;
}

template <typename... Elements>
static teeui::Error drawElements(std::tuple<Elements...>& layout,
                                 const teeui::PixelDrawer& drawPixel) {
    // Error::operator|| is overloaded, so we don't get short circuit
    // evaluation. But we get the first error that occurs. We will still try and
    // draw the remaining elements in the order they appear in the layout tuple.
    return (std::get<Elements>(layout).draw(drawPixel) || ...);
}

static ResponseCode teeuiError2ResponseCode(const teeui::Error& e) {
    switch (e.code()) {
    case teeui::Error::OK:
        return ResponseCode::OK;
    case teeui::Error::NotInitialized:
        return ResponseCode::UIError;
    case teeui::Error::FaceNotLoaded:
        return ResponseCode::UIErrorMissingGlyph;
    case teeui::Error::CharSizeNotSet:
        return ResponseCode::UIError;
    case teeui::Error::GlyphNotLoaded:
        return ResponseCode::UIErrorMissingGlyph;
    case teeui::Error::GlyphNotRendered:
        return ResponseCode::UIErrorMissingGlyph;
    case teeui::Error::GlyphNotExtracted:
        return ResponseCode::UIErrorMissingGlyph;
    case teeui::Error::UnsupportedPixelFormat:
        return ResponseCode::UIError;
    case teeui::Error::OutOfBoundsDrawing:
        return ResponseCode::UIErrorMessageTooLong;
    case teeui::Error::BBoxComputation:
        return ResponseCode::UIErrorMessageTooLong;
    case teeui::Error::OutOfMemory:
        return ResponseCode::UIErrorMessageTooLong;
    case teeui::Error::Localization:
        return ResponseCode::UIError;
    default:
        return ResponseCode::UIError;
    }
}

teeui::Error TrustyConfirmationUI::updateTranslations(uint32_t idx) {
    using namespace teeui;
    if (auto error = updateString<LabelOK>(&layout_[idx]))
        return error;
    if (auto error = updateString<LabelCancel>(&layout_[idx]))
        return error;
    if (auto error = updateString<LabelTitle>(&layout_[idx]))
        return error;
    if (auto error = updateString<LabelHint>(&layout_[idx]))
        return error;
    return Error::OK;
}

ResponseCode TrustyConfirmationUI::start(const char* prompt,
                                         const char* lang_id,
                                         bool inverted,
                                         bool magnified) {
    ResponseCode render_error = ResponseCode::OK;
    enabled_ = true;
    inverted_ = inverted;

    using namespace teeui;

    auto ctx = devices::getDeviceContext(magnified);
    auto deviceCount = ctx.size();

    if (deviceCount < 1) {
        TLOGE("Invalud deviceCount:  %d\n", (int)deviceCount);
        return ResponseCode::UIError;
    }

    fb_info_.resize(deviceCount);
    secure_fb_handle_.resize(deviceCount);
    layout_.resize(deviceCount);

    for (auto i = 0; i < (int)deviceCount; ++i) {
        if (auto rc = secure_fb_open(&secure_fb_handle_[i], &fb_info_[i], i)) {
            TLOGE("secure_fb_open returned  %d\n", rc);
            stop();
            return ResponseCode::UIError;
        }
        if (fb_info_[i].pixel_format != TTUI_PF_RGBA8) {
            TLOGE("Unknown pixel format %u\n", fb_info_[i].pixel_format);
            stop();
            return ResponseCode::UIError;
        }

        if (*(ctx[i]).getParam<RightEdgeOfScreen>() != pxs(fb_info_[i].width) ||
            *(ctx[i]).getParam<BottomOfScreen>() != pxs(fb_info_[i].height)) {
            TLOGE("Framebuffer dimensions do not match panel configuration\n");
            TLOGE("Check device configuration\n");
            stop();
            return ResponseCode::UIError;
        }
    }

    for (auto i = 0; i < (int)deviceCount; ++i) {
        updateColorScheme(&(ctx[i]), inverted_);
        layout_[i] = instantiateLayout(ConfUILayout(), ctx[i]);

        localization::selectLangId(lang_id);
        if (auto error = updateTranslations(i)) {
            stop();
            return teeuiError2ResponseCode(error);
        }

        std::get<LabelBody>(layout_[i])
                .setText({prompt, prompt + strlen(prompt)});

        showInstructions(false /* enable */);
        render_error = renderAndSwap(i);
        if (render_error != ResponseCode::OK) {
            stop();
            return render_error;
        }
    }
    return ResponseCode::OK;
}

ResponseCode TrustyConfirmationUI::renderAndSwap(uint32_t idx) {
    /* All display will be rendering the same content */
    auto drawPixel = teeui::makePixelDrawer([&, this](uint32_t x, uint32_t y,
                                                      teeui::Color color)
                                                    -> teeui::Error {
        TLOGD("px %u %u: %08x", x, y, color);
        size_t pos =
                y * fb_info_[idx].line_stride + x * fb_info_[idx].pixel_stride;
        TLOGD("pos: %zu, bufferSize: %" PRIu32 "\n", pos, fb_info_[idx].size);
        if (pos >= fb_info_[idx].size) {
            return teeui::Error::OutOfBoundsDrawing;
        }
        double alfa = (color & 0xff000000) >> 24;
        alfa /= 255.0;
        auto& pixel =
                *reinterpret_cast<teeui::Color*>(fb_info_[idx].buffer + pos);

        pixel = alfaCombineChannel(0, alfa, color, pixel) |
                alfaCombineChannel(8, alfa, color, pixel) |
                alfaCombineChannel(16, alfa, color, pixel);
        return teeui::Error::OK;
    });

    TLOGI("begin rendering\n");

    teeui::Color bgColor = kColorBackground;
    if (inverted_) {
        bgColor = kColorBackgroundInv;
    }
    uint8_t* line_iter = fb_info_[idx].buffer;
    for (uint32_t yi = 0; yi < fb_info_[idx].height; ++yi) {
        auto pixel_iter = line_iter;
        for (uint32_t xi = 0; xi < fb_info_[idx].width; ++xi) {
            *reinterpret_cast<uint32_t*>(pixel_iter) = bgColor;
            pixel_iter += fb_info_[idx].pixel_stride;
        }
        line_iter += fb_info_[idx].line_stride;
    }

    if (auto error = drawElements(layout_[idx], drawPixel)) {
        TLOGE("Element drawing failed: %u\n", error.code());
        return teeuiError2ResponseCode(error);
    }

    if (auto rc = secure_fb_display_next(secure_fb_handle_[idx],
                                         &fb_info_[idx])) {
        TLOGE("secure_fb_display_next returned  %d\n", rc);
        return ResponseCode::UIError;
    }

    return ResponseCode::OK;
}

ResponseCode TrustyConfirmationUI::showInstructions(bool enable) {
    using namespace teeui;
    if (enabled_ == enable)
        return ResponseCode::OK;
    enabled_ = enable;
    Color color;
    if (enable) {
        if (inverted_)
            color = kColorEnabledInv;
        else
            color = kColorEnabled;
    } else {
        if (inverted_)
            color = kColorDisabledInv;
        else
            color = kColorDisabled;
    }
    ResponseCode rc = ResponseCode::OK;
    for (auto i = 0; i < (int)layout_.size(); ++i) {
        std::get<LabelOK>(layout_[i]).setTextColor(color);
        std::get<LabelCancel>(layout_[i]).setTextColor(color);
        if (enable) {
            rc = renderAndSwap(i);
            if (rc != ResponseCode::OK) {
                stop();
                break;
            }
        }
    }
    return rc;
}

void TrustyConfirmationUI::stop() {
    TLOGI("calling gui stop\n");
    for (auto& secure_fb_handle: secure_fb_handle_) {
        secure_fb_close(secure_fb_handle);
        secure_fb_handle = NULL;
    }
    TLOGI("calling gui stop - done\n");
}
