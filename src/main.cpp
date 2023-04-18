#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <LinkedList.h>

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

#define DEVICE_TIMEOUT          (1000*60*5) // if a device hasn't been seen for greater than DEVICE_TIMEOUT, clear it
// TODO: might raise this threshold to -50 or -55
#define BLE_RSSI_THRESHOLD            (-50) // device is considered "in range" if it's RSSI is at or above this
#define WIFI_RSSI_THRESHOLD           (-40) // device is considered "in range" if it's RSSI is at or above this
#define SCANNING_TIME           (1000*60*3) // TODO: do it more often just for testing

// TODO: how to remove devices seen for too long

unsigned long last_scan_time;
void update_detected_devices();

// 0,1, less than 5, less than 10, more than 10
// enum occupancy {
//   zero, // 0-1
//   one,
//   under_5,
//   under_10,
//   over_10
// };

// enough for 12 hours of data, with a little extra room
int current_i = 0;
int occupancy_metrics[150];

// RSSI (Received signal strength indication): measured in decibels from 0 (zero) to -120 (minus 120)
// closer to 0 (zero) the stronger the signal, which means it's better
int max_RSSI = 1;
int min_RSSI = 1;

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
int scanTime = 5; //In seconds
BLEScan* pBLEScan;

// TODO: move to be its own file
// TODO: might combine with WiFIDetectedDevice to be one class, with property of detected_by maybe
class BLEDetectedDevice {
  public:
    std::string ble_mac_addr;
    int rssi;
    unsigned long time_first_detected;
    unsigned long time_last_detected;
    uint8_t manufacturer_data[100];
    uint8_t company_identifier[3];
    bool advertising_covid_exposure;
};
// stores detected devices within BLE_RSSI_THRESHOLD
LinkedList<BLEDetectedDevice> detected_devices;

void ble_init();
void ble_scan_devices();
int get_in_range_ble_device_count();
int get_in_covid_exposure_ble_device_count();
bool device_seen_before(std::string addr);
void clear_old_devices();

// -- Wi-Fi vars --
// https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino

int wifi_devices_seen = 0;

class WiFiDetectedDevice {
  public:
    std::string wifi_mac_addr;
    int rssi;
    unsigned long time_first_detected;
    unsigned long time_last_detected;
};
// stores detected devices within WIFI_RSSI_THRESHOLD
LinkedList<WiFiDetectedDevice> sniffer_detected_devices;

// Might use the BLE functions in parallel to detect further mobiles as a certain part of the BLE MAC address will not change (see my link regarding BLE above).
// ? look at this, https://www.lairdconnect.com/support/faqs/why-does-ble-mac-address-keep-changing-my-smartphone

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

void wifi_sniff();
int get_in_range_wifi_device_count();
void clear_old_wifi_devices();
bool sniffed_device_before(std::string addr);

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        std::string strAddrData = advertisedDevice.getAddress().toString();

        // For testing purposes, tracks the max and min RSSI seen
        if (advertisedDevice.getRSSI() > max_RSSI || max_RSSI == 1) {
            max_RSSI = advertisedDevice.getRSSI();
        }
        if (advertisedDevice.getRSSI() < min_RSSI || min_RSSI == 1) {
            min_RSSI = advertisedDevice.getRSSI();
        }

        if (device_seen_before(strAddrData) == true) {
            // Serial.println("device seen before");
            return;
        }

        if (advertisedDevice.getRSSI() < BLE_RSSI_THRESHOLD) {
            // Serial.println("device outside range");
            // don't store device if above the top rssi threshold
            return;
        }

        BLEDetectedDevice newDevice;
        newDevice.ble_mac_addr = strAddrData;
        newDevice.rssi = advertisedDevice.getRSSI();

        if (advertisedDevice.haveManufacturerData()) {
            std::string strManufacturerData = advertisedDevice.getManufacturerData();
            strManufacturerData.copy((char *)newDevice.manufacturer_data, strManufacturerData.length(), 0);

            // Logs device's manufacturer data to serial console
            // for (int i = 0; i < strManufacturerData.length(); i++) {
            //     Serial.printf("[%02x]", newDevice.manufacturer_data[i]);
            // }
            // Serial.println();

            // Company Identifier is the first two bytes in little endian order (0x4C00 -> 0x004C)
            // 4c001006131daf78ab78 --> 0x004C == Apple
            // 100340100230 --> 0x0310 == SGL Italia S.r.l.
            newDevice.company_identifier[1] = newDevice.manufacturer_data[0];
            newDevice.company_identifier[0] = newDevice.manufacturer_data[1];
            // Serial.printf("0x%02x%02x\n", newDevice.manufacturer_data[1], newDevice.manufacturer_data[0]);
        }

        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = millis();

        // Can be used to check if a particular service is being advertised
        BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");
        newDevice.advertising_covid_exposure = advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid);

        detected_devices.add(newDevice);

        // BLE_ADDR_PUBLIC (0x00), BLE_ADDR_RANDOM (0x01), BLE_ADDR_PUBLIC_ID (0x02), BLE_ADDR_RANDOM_ID (0x03)
        // Serial.printf("Address Type: %zu \n", (unsigned int)advertisedDevice.getAddressType());
    }
};

void setup() {
    Serial.begin(9600);
    delay(100);

    Serial.println("Starting up...");
    last_scan_time = 0;
    current_i = 0;

    // Initialized for Wi-Fi Sniffing
    nvs_flash_init();
    tcpip_adapter_init();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );

    // TODO: try this in this new order
    // Initializes Wi-Fi Sniffer
    // delay(10);
    // wifi_sniffer_init();

    // Initializes the ESP32 as a BLE device
    // TODO: try using BLEDevice -- static void deinit(bool release_memory = false);
    // ble_init();

    // ! fix crash, something in wifi sniffer init causes ble start scan to crash the esp :(, it was wifi init
    // added deinit around wifi sniff section, but led to other errors when trying to run ble scan and wifi sequentially
    // ble_scan_devices();

    // sometimes ble fails here, or it gets through and wifi sniff has the error below
    // delay(10000);
    //! fix ESP_ERROR_CHECK failed: esp_err_t 0x101 (ESP_ERR_NO_MEM) at 0x40092f4c
    // wifi_sniff();

    // wifi_sniff();
    // delay(1000);
    // ! fix Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.
    // ble_scan_devices();
}

void loop() {
    // Scan every 3 minutes
    if (millis() - last_scan_time > SCANNING_TIME || last_scan_time == 0) {
        last_scan_time = millis();
        update_detected_devices();
    }
}

void update_detected_devices() {
    ble_scan_devices();
    // TODO: try advertisedDevice.getScan()->stop();

    // TODO: could try putting into light sleep
    // ? should wifi sniff be ran as often since it's slow
    wifi_sniff();

    // ? could freeze state and save stuff in flash and then restart
    // ? need to see what reboot type thing is needed in between
    // ? look for more specific example online, dig through docs, or try reboot

    // average numbers to decide on bus stop occupancy at this time
    int occupancy_estimate = 0.4 * get_in_range_wifi_device_count() + 0.3 * get_in_covid_exposure_ble_device_count() + 0.3 * detected_devices.size();
    // Serial.printf(", Estimated Occupancy = %d\n", occupancy_estimate);

    // ** both_count + in_range * weighted + covid_count * weighted + wifi_count * weighted

    // save the current believed “occupancy”
    occupancy_metrics[current_i] = occupancy_estimate;

    // update previous estimated occupancy based on count of devices that have been around for over SCANNING_TIME
    if (current_i > 0) {
        int updated_covid_ble_count = 0;
        int updated_detected_ble_count = 0;
        int updated_detected_wifi_count = 0;

        for (int i = 0; i < detected_devices.size(); i++) {
            if (millis() - detected_devices.get(i).time_first_detected > SCANNING_TIME) {
                if (detected_devices.get(i).advertising_covid_exposure) {
                    updated_covid_ble_count += 1;
                }
                updated_detected_ble_count += 1;
            }
        }

        for (int i = 0; i < sniffer_detected_devices.size(); i++) {
            if (millis() - sniffer_detected_devices.get(i).time_first_detected > SCANNING_TIME) {
                updated_detected_wifi_count += 1;
            }
        }

        int updated_count = 0.4 * updated_detected_wifi_count + 0.3 * updated_covid_ble_count + 0.3 * updated_detected_ble_count;

        if (occupancy_metrics[current_i - 1] != updated_count) {
        // if (occupancy_metrics[current_i - 1] > updated_occupancy_count) {
            Serial.printf("updated occupancy count from %d to %d\n", occupancy_metrics[current_i - 1], updated_count);
        }
        occupancy_metrics[current_i - 1] = updated_count;
    }

    // log occupancy metrics to serial monitor
    Serial.print("Occupancy Over Time = ");
    for (int i = 0; i <= current_i; i++) {
        Serial.printf("%d, ", occupancy_metrics[i]);
    }
    Serial.println();
    
    current_i = current_i + 1;
}

// int calculate_occupancy_estimate()

void ble_init() {
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan(); //create new scan
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    // pBLEScan->setInterval(100); 
    // pBLEScan->setWindow(99);  // less or equal setInterval value
}

void ble_scan_devices() {
    // Init ESP as ble device
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan(); //create new scan
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());

    // Clear out devices that haven't been seen recently
    clear_old_devices();

    max_RSSI = 1;
    min_RSSI = 1;

    // Serial.println("Starting scan... ");
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
    Serial.printf("BLE Devices found: %d", foundDevices.getCount());
    pBLEScan->clearResults();   // delete results fromBLEScan buffer to release memory

    // ! with deinit around BLE, getting
    // hit this issue if set release_memory = true
    // https://github.com/espressif/arduino-esp32/issues/2060
    // [ 60341][E][BLEScan.cpp:402] start(): esp_ble_gap_set_scan_params: err: 259, text: Unknown ESP_ERR error
    // found on github that "Because classic bluetooth is turned on, when you release memory from classic bt then bluetooth controller cant be initialized:"
    BLEDevice::deinit();

    Serial.printf(", RSSI: %d to %d, In Range Count: %d, Covid Count: %d\n", max_RSSI, min_RSSI, get_in_range_ble_device_count(), get_in_covid_exposure_ble_device_count());
    // Serial.println("Scan done!");
}

int get_in_range_ble_device_count() {
    return detected_devices.size();
}

int get_in_covid_exposure_ble_device_count() {
    int count = 0;
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).advertising_covid_exposure) {
            count += 1;
        }
    }
    return count;
}

bool device_seen_before(std::string addr) {
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).ble_mac_addr.compare(addr) == 0) {
            // Update time last detected
            BLEDetectedDevice device = detected_devices.get(i);
            device.time_last_detected = millis();
            detected_devices.set(i, device);
            return true;
        }
    }
    return false;
}

void clear_old_devices() {
    int removed_count = 0;
    for (int i = 0; i < detected_devices.size(); i++) {
        // If device not seen in the last minute, remove it
        if (millis() - detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            // Serial.println("cleared an old device");
            // Serial.printf("time diff - %d\n", millis() - detected_devices.get(i).time_last_detected);
            detected_devices.remove(i);
            removed_count += 1;
        }
    }
    if (removed_count != 0) {
        Serial.printf("%d old devices removed\n", removed_count);
    }
}

esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void wifi_sniffer_init(void) {
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );

  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true); // appears to turn on the wifi scanning
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

//   CONFIG_ESP32_WIFI_TASK_PINNED_TO_CORE_0
//   CONFIG_BT_

    // TODO: Try changing filter esp_wifi_set_promiscuous_filter to WIFI_PROMIS_FILTER_MASK_ALL, see what the diff is
    // by default it is to filter all packets except WIFI_PKT_MISC
}

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch(type) {
    case WIFI_PKT_MGMT: return "MGMT"; // only ever seen this packet type so far
    case WIFI_PKT_DATA: return "DATA";
    default:  
    case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    char addr[20];
    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2], hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
    std::string mac_addr = std::string(addr);
    // Serial.println(mac_addr.c_str());

    // For testing purposes, tracks the max and min RSSI seen
    if (ppkt->rx_ctrl.rssi > max_RSSI || max_RSSI == 1) {
        max_RSSI = ppkt->rx_ctrl.rssi;
    }
    if (ppkt->rx_ctrl.rssi < min_RSSI || min_RSSI == 1) {
        min_RSSI = ppkt->rx_ctrl.rssi;
    }

    // Looks at sender address in packet
    if (sniffed_device_before(mac_addr)) {
        // Serial.println("device seen before");
        return;
    }

    wifi_devices_seen += 1;

    if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
        // Serial.println("device outside range");
        // don't store device if above the top rssi threshold
        return;
    }

    // Serial.printf("rssi seen %d\n", ppkt->rx_ctrl.rssi);

    // Add new detected device to linked list
    WiFiDetectedDevice newDevice;
    newDevice.wifi_mac_addr = mac_addr;
    newDevice.rssi = ppkt->rx_ctrl.rssi;
    newDevice.time_first_detected = millis();
    newDevice.time_last_detected = millis();
    sniffer_detected_devices.add(newDevice);
}

void wifi_sniff() {
    // Initializes Wi-Fi Sniffer
    delay(10);
    wifi_sniffer_init();
    // Serial.println("initialized wi-fi");

    // Serial.println("Starting wi-fi sniff...");
    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_wifi_devices();

    max_RSSI = 1;
    min_RSSI = 1;

    wifi_devices_seen = 0;

    // Perform wifi sniffing for 2.5 seconds per channel, 24 channels -> 60 seconds total
    // esp_wifi_set_promiscuous(true);
    for (int i = 1; i < WIFI_CHANNEL_MAX; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        // channel = (channel % WIFI_CHANNEL_MAX) + 1;
        
        delay(2500); // TODO: change to be non-blocking
        // Serial.printf("device count after channel %d = %d\n", i, wifi_devices_seen);
    }
    // esp_wifi_set_promiscuous(false);
    ESP_ERROR_CHECK( esp_wifi_stop() );
    ESP_ERROR_CHECK( esp_wifi_deinit() );
    // Serial.println("killed wi-fi");

    Serial.printf("Wi-Fi Devices found: %d, RSSI: %d to %d, In Range Count: %d\n", wifi_devices_seen, max_RSSI, min_RSSI, get_in_range_wifi_device_count());
    // Serial.println("Scan done!");
}

bool sniffed_device_before(std::string addr) {
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        if (sniffer_detected_devices.get(i).wifi_mac_addr.compare(addr) == 0) {
            // Update time last detected
            WiFiDetectedDevice device = sniffer_detected_devices.get(i);
            device.time_last_detected = millis();
            sniffer_detected_devices.set(i, device);
            return true;
        }
    }
    return false;
}

void clear_old_wifi_devices() {
    int removed_count = 0;
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        // If device not seen in the last minute, remove it
        if (millis() - sniffer_detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            // Serial.println("cleared an old device");
            sniffer_detected_devices.remove(i);
            removed_count += 1;
        }
    }
    if (removed_count != 0) {
        Serial.printf("%d old devices removed\n", removed_count);
    }
}

int get_in_range_wifi_device_count() {
    return sniffer_detected_devices.size();
}