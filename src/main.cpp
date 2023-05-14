#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)

// if a device hasn't been seen for greater than DEVICE_TIMEOUT, clear it
#define DEVICE_TIMEOUT          (1000*60*4) 
// RSSI (Received signal strength indication): measured in decibels from 0 (zero) to -120 (minus 120)
// closer to 0 (zero) the stronger the signal, which means it's better
// device is considered "in range" if it's RSSI is at or above this
#define BLE_RSSI_THRESHOLD            (-85) 
#define WIFI_RSSI_THRESHOLD           (-75)
// scan to check occupancy every 3 minutes
#define SCANNING_TIME           (1000*60*3)

unsigned long last_scan_time;

enum oui_class {
  important,
  not_important,
  unknown
};

class DetectedDevice {
  public:
    std::string mac_addr;
    int8_t rssi;
    unsigned long time_first_detected;
    unsigned long time_last_detected;
    bool advertising_covid_exposure;
    oui_class oui;
};
// TODO: maybe cap number it could store here, to prevent possible size crash ??
std::vector<DetectedDevice> ble_detected_devices;
std::vector<DetectedDevice> wifi_detected_devices;

uint8_t current_i = 0;
uint8_t occupancy_metrics[250]; // Measures occupancy 20 times an hour * 12 hours a day = 240, 250 leaves enough space for a full day of occupancy data
uint16_t wait_time_current_i = 0;
uint8_t wait_time_metrics[2400]; // Measures wait time 20 times an hour * 12 hours a day * on avg. 10 person occupancy per time

void update_detected_devices();
bool device_seen_before(std::vector<DetectedDevice> *device_list, std::string addr, int rssi);
void clear_old_devices(std::vector<DetectedDevice> *device_list);

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
uint8_t scanTime = 3; // seconds
BLEScan* pBLEScan;

unsigned long ble_scan_start_time;

void ble_init();
void ble_scan_devices();

// -- Wi-Fi vars --
// https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino

unsigned long wifi_scan_start_time;

// MAC Addresses start with the manufacturer's organizationally unique identifier (OUI)
// For occupancy tracking, important OUI's to track include the following manufacturer's (Apple, Inc., Google, Inc., Samsung Electronics Co.,Ltd, etc.) and not important are networking related companies
#define IMPORTANT_MAC_OUIS_SIZE 31
#define NOT_IMPORTANT_MAC_OUIS_SIZE 8
std::string important_mac_ouis[IMPORTANT_MAC_OUIS_SIZE] = { "3c:06:30", "5c:e9:1e", "68:d9:3c", "4c:32:75", "c8:89:f3", "f4:d4:88", "80:65:7c", "68:2f:67", "00:25:00", "3c:22:fb", "bc:d0:74", "c0:bd:c8", "ac:c9:06", "54:21:9d", "98:01:a7", "bc:d0:74", "58:40:4e", "14:7d:da", "f8:ff:c2", "cc:f4:11", "64:5d:f4", "f8:0f:f9", "14:22:3b", "e0:b5:5f", "1c:57:dc", "fc:e2:6c", "20:15:82", "a0:99:9b", "f0:18:98", "38:f9:d3", "d0:1b:49" };
std::string not_important_mac_ouis[NOT_IMPORTANT_MAC_OUIS_SIZE] = { "d4:20:b0", "00:30:44", "5c:5b:35", "00:0e:8e", "28:80:a2", "00:3E:73", "3c:e4:b0", "94:e3:6d" }; // mainly networking related communications

void wifi_sniff();
oui_class get_mac_addr_oui_class(std::string mac_addr);
bool is_mac_addr_oui_important(std::string mac_addr_oui);
bool is_mac_addr_oui_not_important(std::string mac_addr_oui);

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

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        std::string strAddrData = advertisedDevice.getAddress().toString();

        BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");

        if (device_seen_before(&ble_detected_devices, strAddrData, advertisedDevice.getRSSI()) == true || (advertisedDevice.getRSSI() < BLE_RSSI_THRESHOLD && !advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid))) {
            // don't store device if it's already stored, or RSSI is too low and it's not advertising the covid exposure notification
            return;
        }

        DetectedDevice newDevice;
        newDevice.mac_addr = strAddrData;
        newDevice.rssi = advertisedDevice.getRSSI();

        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        
        // Used to check if a Covid Exposure service is being advertised
        // https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ExposureNotification-BluetoothSpecificationv1.2.pdf?1
        newDevice.advertising_covid_exposure = advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid);

        ble_detected_devices.push_back(newDevice);
    }
};

void setup() {
    Serial.begin(9600);
    delay(100);

    Serial.println("Starting up...");
    last_scan_time = 0;
    current_i = 0;
    wait_time_current_i = 0;

    // Initialized for Wi-Fi Sniffing
    nvs_flash_init();
    tcpip_adapter_init();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
}

void loop() {
    // Scan for devices every SCANNING_TIME
    if (millis() - last_scan_time > SCANNING_TIME || last_scan_time == 0) {
        last_scan_time = millis();
        update_detected_devices();
    }
}

void update_detected_devices() {
    // Scan for BLE devices
    ble_scan_devices();

    // Sniff Wi-Fi traffic
    wifi_sniff();

    // Gather occupancy metrics for calculation
    uint8_t ble_in_range_device_count = 0;
    uint8_t ble_covid_device_count = 0;
    uint8_t wifi_in_range_device_count = 0;
    uint8_t wifi_important_device_count = 0;

    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = wifi_detected_devices[i].rssi >= WIFI_RSSI_THRESHOLD;
        if (wifi_detected_devices[i].oui == unknown) {
            // unknown devices have to pass a higher RSSI threshold to be considered in range
            pass_rssi = wifi_detected_devices[i].rssi >= -65;
        }
        bool been_around = millis() - wifi_detected_devices[i].time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = wifi_detected_devices[i].time_last_detected >= wifi_scan_start_time;

        int time_around = wifi_detected_devices[i].time_last_detected - wifi_detected_devices[i].time_first_detected;
              
        if (wifi_detected_devices[i].oui == important && seen_in_last_scan) {
            wifi_important_device_count += 1;
        } else if (pass_rssi && been_around && seen_in_last_scan) {
            wifi_in_range_device_count += 1;
        }
    }

    for (int i = 0; i < ble_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = ble_detected_devices[i].rssi >= BLE_RSSI_THRESHOLD;
        bool been_around = millis() - ble_detected_devices[i].time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = ble_detected_devices[i].time_last_detected >= ble_scan_start_time;

        int time_around = ble_detected_devices[i].time_last_detected - ble_detected_devices[i].time_first_detected;

        if (pass_rssi && been_around && seen_in_last_scan) {
            ble_in_range_device_count += 1;
        }

        if (ble_detected_devices[i].advertising_covid_exposure && been_around && seen_in_last_scan) {
            ble_covid_device_count += 1;
        }
    }

    Serial.printf("*[BLE DEVICES_STORED=%d, IN_RANGE_COUNT=%d, COVID_COUNT=%d]\n", ble_detected_devices.size(), ble_in_range_device_count, ble_covid_device_count);
    Serial.printf("*[WIFI DEVICES_STORED=%d, IN_RANGE_COUNT=%d, IMPORTANT_COUNT=%d]\n", wifi_detected_devices.size(), wifi_in_range_device_count, wifi_important_device_count);

    // Average numbers to decide on bus stop occupancy at this time
    float wifi_estimate = wifi_important_device_count + (wifi_in_range_device_count / 2.0);
    float ble_estimate = (0.5 * ble_in_range_device_count + 0.5 * ble_covid_device_count) / 2.0;

    int occupancy_estimate = (wifi_estimate + ble_estimate) / 2;

    // Save the current estimated occupancy
    occupancy_metrics[current_i] = occupancy_estimate;

    // Get wait times of relevant devices
    uint8_t ble_in_range_wait_times[ble_in_range_device_count];
    int cur_i_ble_in_range = 0;
    uint8_t ble_covid_wait_times[ble_covid_device_count];
    int cur_i_ble_covid = 0;
    uint8_t wifi_in_range_wait_times[wifi_in_range_device_count];
    int cur_i_wifi_in_range = 0;
    uint8_t wifi_important_wait_times[wifi_important_device_count];
    int cur_i_wifi_important = 0;

    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = wifi_detected_devices[i].rssi >= WIFI_RSSI_THRESHOLD;
        if (wifi_detected_devices[i].oui == unknown) {
            // unknown devices have to pass a higher RSSI threshold to be considered in range
            pass_rssi = wifi_detected_devices[i].rssi >= -65;
        }
        bool been_around = millis() - wifi_detected_devices[i].time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = wifi_detected_devices[i].time_last_detected >= wifi_scan_start_time;

        int time_around = wifi_detected_devices[i].time_last_detected - wifi_detected_devices[i].time_first_detected;
              
        if (wifi_detected_devices[i].oui == important && seen_in_last_scan) {
            wifi_important_wait_times[cur_i_wifi_important] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_wifi_important += 1;
        } else if (pass_rssi && been_around && seen_in_last_scan) {
            wifi_in_range_wait_times[cur_i_wifi_in_range] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_wifi_in_range += 1;
        }
    }

    for (int i = 0; i < ble_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = ble_detected_devices[i].rssi >= BLE_RSSI_THRESHOLD;
        bool been_around = millis() - ble_detected_devices[i].time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = ble_detected_devices[i].time_last_detected >= ble_scan_start_time;

        int time_around = ble_detected_devices[i].time_last_detected - ble_detected_devices[i].time_first_detected;

        if (pass_rssi && been_around && seen_in_last_scan) {
            ble_in_range_wait_times[cur_i_ble_in_range] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_ble_in_range += 1;
        }

        if (ble_detected_devices[i].advertising_covid_exposure && been_around && seen_in_last_scan) {
            ble_covid_wait_times[cur_i_ble_covid] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_ble_covid += 1;
        }
    }

    // Store current wait times rounded to nearest 0, 3, 6 min, etc.
    // First, take wait times from do care list, then go to covid, wifi in-range, and ble in-range
    cur_i_wifi_important = 0;
    cur_i_ble_covid = 0;
    cur_i_wifi_in_range = 0;
    cur_i_ble_in_range = 0;
    for (int i = 0; i < occupancy_estimate; i++) {
        if (cur_i_wifi_important < wifi_important_device_count) {
            // Serial.print("getting wait time from wifi important ");
            wait_time_metrics[wait_time_current_i] = wifi_important_wait_times[cur_i_wifi_important];
            // Serial.println(wifi_important_wait_times[cur_i_wifi_important]);
            cur_i_wifi_important += 1;
        } else if (cur_i_ble_covid < ble_covid_device_count) {
            // Serial.print("getting wait time from ble covid ");
            wait_time_metrics[wait_time_current_i] = ble_covid_wait_times[cur_i_ble_covid];
            // Serial.println(ble_covid_wait_times[cur_i_ble_covid]);
            cur_i_ble_covid += 1;
        } else if (cur_i_wifi_in_range < wifi_in_range_device_count) {
            // Serial.print("getting wait time from wifi in range ");
            wait_time_metrics[wait_time_current_i] = wifi_in_range_wait_times[cur_i_wifi_in_range];
            // Serial.println(wifi_in_range_wait_times[cur_i_wifi_in_range]);
            cur_i_wifi_in_range += 1;
        } else if (cur_i_ble_in_range < ble_in_range_device_count) {
            // Serial.print("getting wait time from ble in range ");
            wait_time_metrics[wait_time_current_i] = ble_in_range_wait_times[cur_i_ble_in_range];
            // Serial.println(ble_in_range_wait_times[cur_i_ble_in_range]);
            cur_i_ble_in_range += 1;
        }
        
        wait_time_current_i += 1;
    }

    // log occupancy metrics to serial monitor
    Serial.print("Occupancy Over Time = ");
    // use only <=, less than or equal to, here since current_i is not updated until after here
    for (int i = 0; i <= current_i; i++) {
        Serial.printf("%d, ", occupancy_metrics[i]);
    }
    Serial.println();

    // log wait time metrics to serial monitor
    Serial.print("Current Wait Times = ");
    // use only <, less than, here since wait_time_current_i is already updated to next index to fill in above
    for (int i = 0; i < wait_time_current_i; i++) {
        Serial.printf("%d, ", wait_time_metrics[i]);
    }
    Serial.println();
    
    current_i = current_i + 1;

    // To protect against using too much memory, remove some devices
    if (ble_detected_devices.size() + wifi_detected_devices.size() > 250) {
        ble_detected_devices.erase(std::remove_if(ble_detected_devices.begin(), ble_detected_devices.end(), [&](const DetectedDevice& d) {
            return d.time_last_detected < ble_scan_start_time;
        }), ble_detected_devices.end());

        wifi_detected_devices.erase(std::remove_if(wifi_detected_devices.begin(), wifi_detected_devices.end(), [&](const DetectedDevice& d) {
            return d.time_last_detected < wifi_scan_start_time;
        }), wifi_detected_devices.end());
    }
}

void ble_scan_devices() {
    ble_scan_start_time = millis();

    // Clear out devices that haven't been seen recently
    clear_old_devices(&ble_detected_devices);
    
    // Init BLE device
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);

    // Delete results fromBLEScan buffer to release memory
    pBLEScan->clearResults();   

    // Deinit BLE device
    BLEDevice::deinit();
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
}

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch(type) {
    case WIFI_PKT_MGMT: return "MGMT";
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

    // sender/source address
    char addr[20];
    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    std::string mac_addr = std::string(addr);
    // Serial.println(mac_addr.c_str());

    // receiver/destination address
    char d_addr[20];
    sprintf(d_addr, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr1[0],hdr->addr1[1],hdr->addr1[2], hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
    std::string destination_addr = std::string(d_addr);

    // filtering address
    char f_addr[20];
    sprintf(f_addr, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr3[0],hdr->addr3[1],hdr->addr3[2], hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
    std::string filtering_addr = std::string(f_addr);

    // Looks at sender address in packet
    if (mac_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !device_seen_before(&wifi_detected_devices, mac_addr, ppkt->rx_ctrl.rssi)) {
        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // only store device if meets the wifi rssi threshold requirement
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = mac_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(mac_addr);
        wifi_detected_devices.push_back(newDevice);
    }

    // Looks at sender address in packet
    if (destination_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !device_seen_before(&wifi_detected_devices, destination_addr, ppkt->rx_ctrl.rssi)) {
        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // only store device if meets the wifi rssi threshold requirement
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = destination_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(destination_addr);
        wifi_detected_devices.push_back(newDevice);
    }

    // Looks at sender address in packet
    if (filtering_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !device_seen_before(&wifi_detected_devices, filtering_addr, ppkt->rx_ctrl.rssi)) {
        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // only store device if meets the wifi rssi threshold requirement
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = filtering_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(filtering_addr);
        wifi_detected_devices.push_back(newDevice);
    }
}

void wifi_sniff() {
    wifi_scan_start_time = millis();

    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_devices(&wifi_detected_devices);

    // Init Wi-Fi Sniffer
    wifi_sniffer_init();

    // Perform wifi sniffing for 2 seconds per channel, 11 channels -> 22 seconds total
    for (int i = 1; i <= 11; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        
        delay(2000);
    }

    ESP_ERROR_CHECK( esp_wifi_stop() );

    // Deinit Wi-Fi Sniffer
    ESP_ERROR_CHECK( esp_wifi_deinit() );
}

bool device_seen_before(std::vector<DetectedDevice> *device_list, std::string addr, int rssi) {
    for (int i = 0; i < device_list->size(); i++) {
        if (device_list->at(i).mac_addr.compare(addr) == 0) {
            // Update time last detected and rssi
            device_list->at(i).time_last_detected = millis();
            device_list->at(i).rssi = rssi;
            return true;
        }
    }
    return false;
}

void clear_old_devices(std::vector<DetectedDevice> *device_list) {
    device_list->erase(std::remove_if(device_list->begin(), device_list->end(), [&](const DetectedDevice& d) {
        return millis() - d.time_last_detected > DEVICE_TIMEOUT;
    }), device_list->end());

    device_list->shrink_to_fit();
}

bool is_mac_addr_oui_important(std::string mac_addr_oui) {
    for (int i = 0; i < IMPORTANT_MAC_OUIS_SIZE; i++) {
        if (important_mac_ouis[i].compare(mac_addr_oui.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

bool is_mac_addr_oui_not_important(std::string mac_addr_oui) {
    for (int i = 0; i < NOT_IMPORTANT_MAC_OUIS_SIZE; i++) {
        if (not_important_mac_ouis[i].compare(mac_addr_oui.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

oui_class get_mac_addr_oui_class(std::string mac_addr) {
    mac_addr[8] = '\0';
    if (is_mac_addr_oui_important(mac_addr)) {
        return important;
    } else if (is_mac_addr_oui_not_important(mac_addr)) {
        return not_important;
    }
    return unknown;
}