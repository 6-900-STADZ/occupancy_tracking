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
#define RSSI_THRESHOLD                (-60) // device is considered "in range" if it's RSSI is at or above this
#define SCANNING_TIME           (1000*60*3)

unsigned long last_scan_time;
int get_occupancy();

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
int scanTime = 5; //In seconds
BLEScan* pBLEScan;

// RSSI (Received signal strength indication): measured in decibels from 0 (zero) to -120 (minus 120)
// closer to 0 (zero) the stronger the signal, which means it's better
int max_RSSI = 1;
int min_RSSI = 1;

// TODO: move to be its own file
// TODO: might combine with WiFIDetectedDevice to be one class, with property of detected_by maybe
class BLEDetectedDevice {
  public:
    std::string ble_mac_addr;
    int rssi;
    unsigned long time_last_detected;
    uint8_t manufacturer_data[100];
    uint8_t company_identifier[3];
    bool advertising_covid_exposure;
};
LinkedList<BLEDetectedDevice> detected_devices;

void ble_scan_devices();
int get_in_range_device_count();
int get_in_covid_exposure_device_count();
int get_in_range_and_covid_exposure_device_count();
bool device_seen_before(std::string addr);
void clear_old_devices();

// -- Wi-Fi vars --
// https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino

int max_wifi_RSSI = 1;
int min_wifi_RSSI = 1;

class WiFiDetectedDevice {
  public:
    std::string wifi_mac_addr;
    int rssi;
    unsigned long time_last_detected;
};
LinkedList<WiFiDetectedDevice> sniffer_detected_devices;

// ? prob won't work if phone's wi-fi is off
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

        if (device_seen_before(strAddrData) == true) {
            // Serial.println("device seen before");
            return;
        }

        // TODO: also don't store device if above the top rssi threshold

        BLEDetectedDevice newDevice;
        newDevice.ble_mac_addr = strAddrData;
        newDevice.rssi = advertisedDevice.getRSSI();

        if (advertisedDevice.haveManufacturerData()) {
            std::string strManufacturerData = advertisedDevice.getManufacturerData();
            strManufacturerData.copy((char *)newDevice.manufacturer_data, strManufacturerData.length(), 0);

            // Logs device's manufacturer data to serial console
            // TODO: move to be a function on the BLEDetectedDevice class 
            // for (int i = 0; i < strManufacturerData.length(); i++) {
            //     Serial.printf("[%02x]", newDevice.manufacturer_data[i]);
            // }
            // Serial.println();

            // Company Identifier is the first two bytes in little endian order (0x4C00 -> 0x004C)
            // 4c001006131daf78ab78 --> 0x004C == Apple
            // 100340100230 --> 0x0310 == SGL Italia S.r.l.
            newDevice.company_identifier[1] = newDevice.manufacturer_data[0];
            newDevice.company_identifier[0] = newDevice.manufacturer_data[1];
            // TODO: move to be a function on the BLEDetectedDevice class 
            // Serial.printf("0x%02x%02x\n", newDevice.manufacturer_data[1], newDevice.manufacturer_data[0]);
        }

        newDevice.time_last_detected = millis();

        // Can be used to check if a particular service is being advertised
        BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");
        newDevice.advertising_covid_exposure = advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid);

        detected_devices.add(newDevice);

        // BLE_ADDR_PUBLIC (0x00), BLE_ADDR_RANDOM (0x01), BLE_ADDR_PUBLIC_ID (0x02), BLE_ADDR_RANDOM_ID (0x03)
        // Serial.printf("Address Type: %zu \n", (unsigned int)advertisedDevice.getAddressType());

        // For testing purposes, tracks the max and min RSSI seen
        if (advertisedDevice.getRSSI() > max_RSSI || max_RSSI == 1) {
            max_RSSI = advertisedDevice.getRSSI();
        }
        if (advertisedDevice.getRSSI() < min_RSSI || min_RSSI == 1) {
            min_RSSI = advertisedDevice.getRSSI();
        }
    }
};

void setup() {
    Serial.begin(9600);
    delay(100);

    Serial.println("Starting up...");
    last_scan_time = 0;

    // Initializes the ESP32 as a BLE device
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan(); //create new scan
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(false); //active scan uses more power, but get results faster
    pBLEScan->setInterval(100); 
    pBLEScan->setWindow(99);  // less or equal setInterval value
    // TODO: try using BLEDevice -- static void deinit(bool release_memory = false);

    // Initializes Wi-Fi Sniffer
    // delay(10);
    // wifi_sniffer_init();

    // TODO: fix crash, something in wifi sniffer init causes ble start scan to crash the esp :(, it was wifi init
    // added deinit around wifi sniff section, but led to other errors when trying to run ble scan and wifi sequentially
    // ble_scan_devices();

    // sometimes ble fails here, or it gets through and wifi sniff has the error below
    // delay(10000);
    // TODO: fix ESP_ERROR_CHECK failed: esp_err_t 0x101 (ESP_ERR_NO_MEM) at 0x40092f4c
    // wifi_sniff();

    // wifi_sniff();
    // delay(1000);
    // TODO: fix Guru Meditation Error: Core  0 panic'ed (StoreProhibited). Exception was unhandled.
    // ble_scan_devices();
}

void loop() {
    // Scan every 3 minutes
    if (millis() - last_scan_time > SCANNING_TIME) {
        last_scan_time = millis();
        get_occupancy();
    }
}

int get_occupancy() {
    // TODO: can these be synchronous since wifi_sniff is kinda slow, running through various channels
    // ? should wifi sniff be ran as often since it's slow
    ble_scan_devices();
    // wifi_sniff();

    // average numbers to decide on bus stop occupancy at this time
    int occupancy_estimate = 0.6 * get_in_range_and_covid_exposure_device_count() + 0.4 * get_in_range_device_count();
    Serial.printf("Estimated Occupancy = %d\n", occupancy_estimate);

    // Max RSSI: -48  --  Min RSSI: -102  --  In Range Device Count: 4  --  Covid Exposure Count: 16  --  Both Count: 0  --  Total Device Count: 214
    // Scan done!
    // Estimated Occupancy = 1

    return occupancy_estimate;
}

void ble_scan_devices() {
    // Clear out devices that haven't been seen recently
    clear_old_devices();

    Serial.println("Starting scan... ");
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
    Serial.println("after ble scan start");
    // Serial.print("\nDevices found: ");
    // Serial.println(foundDevices.getCount());
    pBLEScan->clearResults();   // delete results fromBLEScan buffer to release memory

    Serial.print("\nMax RSSI: ");
    Serial.print(max_RSSI);
    Serial.print("  --  Min RSSI: ");
    Serial.print(min_RSSI);
    Serial.print("  --  In Range Device Count: ");
    Serial.printf("%d", get_in_range_device_count());
    Serial.print("  --  Covid Exposure Count: ");
    Serial.printf("%d", get_in_covid_exposure_device_count());
    Serial.print("  --  Both Count: ");
    Serial.printf("%d", get_in_range_and_covid_exposure_device_count());
    Serial.print("  --  Total Device Count: ");
    Serial.printf("%d\n", detected_devices.size());
    Serial.println("Scan done!");
}

int get_in_range_device_count() {
    int count = 0;
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).rssi > RSSI_THRESHOLD) {
            count += 1;
        }
    }
    return count;
}

int get_in_covid_exposure_device_count() {
    int count = 0;
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).advertising_covid_exposure) {
            count += 1;
        }
    }
    return count;
}

int get_in_range_and_covid_exposure_device_count() {
    int count = 0;
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).advertising_covid_exposure && detected_devices.get(i).rssi > RSSI_THRESHOLD) {
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
            Serial.println("cleared an old device");
            Serial.printf("time diff - %d\n", millis() - detected_devices.get(i).time_last_detected);
            detected_devices.remove(i);
            removed_count += 1;
        }
    }
    Serial.printf("%d old devices removed\n", removed_count);
}

esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void wifi_sniffer_init(void) {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );

  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true); // appears to turn on the wifi scanning
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

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

    // Looks at sender address in packet
    if (sniffed_device_before(mac_addr)) {
        // Serial.println("device seen before");
        return;
    }

    // Serial.println(mac_addr.c_str());

    // For testing purposes, tracks the max and min RSSI seen
    if (ppkt->rx_ctrl.rssi > max_wifi_RSSI || max_wifi_RSSI == 1) {
        max_wifi_RSSI = ppkt->rx_ctrl.rssi;
    }
    if (ppkt->rx_ctrl.rssi < min_wifi_RSSI || min_wifi_RSSI == 1) {
        min_wifi_RSSI = ppkt->rx_ctrl.rssi;
    }

    // Add new detected device to linked list
    WiFiDetectedDevice newDevice;
    newDevice.wifi_mac_addr = mac_addr;
    newDevice.rssi = ppkt->rx_ctrl.rssi;
    newDevice.time_last_detected = millis();
    sniffer_detected_devices.add(newDevice);
}

void wifi_sniff() {
    // Initializes Wi-Fi Sniffer
    delay(10);
    wifi_sniffer_init();
    Serial.println("initialized wi-fi");

    Serial.println("starting wi-fi sniff...");
    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_wifi_devices();

    // Perform wifi sniffing for 3 seconds per channel
    // esp_wifi_set_promiscuous(true);
    for (int i = 1; i < WIFI_CHANNEL_MAX; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        // channel = (channel % WIFI_CHANNEL_MAX) + 1;
        
        delay(3000); // TODO: change to be non-blocking
    }
    // esp_wifi_set_promiscuous(false);
    ESP_ERROR_CHECK( esp_wifi_stop() );
    ESP_ERROR_CHECK( esp_wifi_deinit() );
    Serial.println("killed wi-fi");

    Serial.print("\nMax Wifi RSSI: ");
    Serial.print(max_wifi_RSSI);
    Serial.print("  --  Min Wifi RSSI: ");
    Serial.print(min_wifi_RSSI);
    Serial.print("  --  Wifi In Range Device Count: ");
    Serial.printf("%d, %d\n", get_in_range_wifi_device_count(), sniffer_detected_devices.size());
    Serial.println("Scan done!");
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
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        // If device not seen in the last minute, remove it
        if (millis() - sniffer_detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            // Serial.println("cleared an old device");
            sniffer_detected_devices.remove(i);
        }
    }
}

int get_in_range_wifi_device_count() {
    int count = 0;
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        if (sniffer_detected_devices.get(i).rssi > RSSI_THRESHOLD) {
            count += 1;
        }
    }
    return count;
}