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

// if a device hasn't been seen for greater than DEVICE_TIMEOUT, clear it
#define DEVICE_TIMEOUT          (1000*60*4) 
// device is considered "in range" if it's RSSI is at or above this
#define BLE_RSSI_THRESHOLD            (-85) 
#define WIFI_RSSI_THRESHOLD           (-75)
// scan to check occupancy every 3 minutes
#define SCANNING_TIME           (1000*60*3)

unsigned long last_scan_time;
void update_detected_devices();

uint8_t current_i = 0;
uint8_t occupancy_metrics[250]; // Measures occupancy 20 times an hour * 12 hours a day = 240, 250 leaves enough space for a full day of occupancy data
// TODO: 1D array, zoe splits it on her end
// TODO: add function to extend this array if it gets too small from 6.08
uint8_t wait_time_metrics[2400]; // Measures wait time 20 times an hour * 12 hours a day * on avg. 10 person occupancy per time

// RSSI (Received signal strength indication): measured in decibels from 0 (zero) to -120 (minus 120)
// closer to 0 (zero) the stronger the signal, which means it's better

// ** testing purposes **
uint8_t channel = 0;
bool logOccupancy = true;
bool logWifiMacAddr = false;
bool logBLEMacAddr = false;
bool logMacAddrSeen = true;
unsigned long start_time;
uint8_t ble_detected_count = 0;
uint8_t wifi_detected_count = 0;
int wifi_devices_seen = 0;

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
uint8_t scanTime = 1; // seconds
BLEScan* pBLEScan;

unsigned long ble_scan_start_time;
unsigned long wifi_scan_start_time;

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

    // ** for testing purposes
    uint8_t wifi_channel;
    uint8_t pckt_addr_num;
};
LinkedList<DetectedDevice> ble_detected_devices;
LinkedList<DetectedDevice> wifi_detected_devices;

void ble_init();
void ble_scan_devices();
int get_in_range_ble_device_count();
int get_covid_exposure_ble_device_count();
bool device_seen_before(std::string addr, int rssi);
void clear_old_devices();

// -- Wi-Fi vars --
// https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino

// MAC Addresses start with the manufacturer's organizationally unique identifier (OUI)
// For occupancy tracking, important OUI's to track include the following manufacturer's
// - Apple, Inc., Google, Inc., Samsung Electronics Co.,Ltd, Motorola Mobility LLC, a Lenovo Company, LG Electronics (Mobile Communications)
#define IMPORTANT_MAC_OUIS_SIZE 8
#define NOT_IMPORTANT_MAC_OUIS_SIZE 3
// amazon tech 90:a8:22, e0:f7:28
// google f8:0f:f9 (added)
// samsung c0:bd:c8 (added)
// TODO: scrape for more of these values
std::string important_mac_ouis[IMPORTANT_MAC_OUIS_SIZE] = { "20:15:82", "00:25:00", "f8:0f:f9", "68:d9:3c", "5c:e9:1e", "1c:57:dc", "c0:bd:c8", "38:f9:d3" };
std::string not_important_mac_ouis[NOT_IMPORTANT_MAC_OUIS_SIZE] = { "00:3E:73", "d4:20:b0", "5c:5b:35" }; // mainly networking related communications

void wifi_sniff();
void clear_old_wifi_devices();
bool sniffed_device_before(std::string addr, int rssi);
oui_class get_mac_addr_oui_class(std::string mac_addr);
bool is_mac_addr_oui_important(std::string mac_addr_oui);
bool is_mac_addr_oui_not_important(std::string mac_addr_oui);
int get_in_range_wifi_device_count();
int get_important_wifi_device_count();
int get_not_not_important_wifi_device_count();

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

        if (device_seen_before(strAddrData, advertisedDevice.getRSSI()) == true || (advertisedDevice.getRSSI() < BLE_RSSI_THRESHOLD && !advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid))) {
            // don't store device if it's already stored, or RSSI is too low and it's not advertising the covid exposure notification
            return;
        }

        DetectedDevice newDevice;
        newDevice.mac_addr = strAddrData;
        newDevice.rssi = advertisedDevice.getRSSI();

        // TODO: does millis reset after going into sleep btwn scans ??
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        
        // Used to check if a Covid Exposure service is being advertised
        // https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ExposureNotification-BluetoothSpecificationv1.2.pdf?1
        newDevice.advertising_covid_exposure = advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid);

        ble_detected_devices.add(newDevice);
    }
};

void setup() {
    Serial.begin(9600);
    delay(100);

    Serial.println("Starting up...");
    last_scan_time = 0;
    current_i = 0;

    // ** for testing purposes
    start_time = millis();

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

    // ** for log testing purposes
    Serial.print("%");

    // Sniff Wi-Fi traffic
    wifi_sniff();

    // Average numbers to decide on bus stop occupancy at this time
    float wifi_estimate = get_important_wifi_device_count() + (get_in_range_wifi_device_count() + get_not_not_important_wifi_device_count()) / 2.0;
    float ble_estimate = (0.5 * get_in_range_ble_device_count() + 0.5 * get_covid_exposure_ble_device_count()) / 2.0;

    int occupancy_estimate = (wifi_estimate + ble_estimate) / 2;

    // save the current believed “occupancy”
    occupancy_metrics[current_i] = occupancy_estimate;

    // Store current wait times rounded to nearest 0, 3, 6 min, etc.
    // TODO: need this to be size of occupancy estimate, how to decide which devices to use tho ??
    // int wait_times[occupancy_estimate];
    // TODO: fill in wait_time_metrics

    // first priority is to keep important mac oui wait times
    // int cur_i = 0;
    // for (int i = 0; i < wifi_detected_devices.size(); i++) {
    //     bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;

    //     if (wifi_detected_devices.get(i).oui == important && seen_in_last_scan && cur_i < occupancy_estimate) {
    //         int time_around = ble_detected_devices.get(i).time_last_detected - ble_detected_devices.get(i).time_first_detected;
    //         Serial.print((time_around / (60.0*1000.0)) + 0.5);
    //         wait_times[cur_i] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
    //         cur_i += 1;
    //     }
    // }

    // int num_filled_in = 0;
    // if (cur_i < occupancy_estimate) {
    //     // TODO:
    //     for (int i = 0; i < wifi_detected_devices.size(); i++) {
    //         bool pass_rssi = wifi_detected_devices.get(i).rssi >= WIFI_RSSI_THRESHOLD;
    //         if (wifi_detected_devices.get(i).oui == unknown) {
    //             // unknown devices have to pass a higher RSSI threshold to be considered in range
    //             pass_rssi = wifi_detected_devices.get(i).rssi >= -65;
    //         }
    //         bool been_around = millis() - wifi_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
    //         bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;

    //         if (wifi_detected_devices.get(i).oui == not_important && pass_rssi && been_around && seen_in_last_scan && cur_i < occupancy_estimate) {
    //             int time_around = ble_detected_devices.get(i).time_last_detected - ble_detected_devices.get(i).time_first_detected;
    //             wait_times[cur_i] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
    //             cur_i += 1;
    //         }
    //     }

    //     // TODO: do more testing, to decide how to average and consolidate wait times down to total based on occupancy estimate
    //     for (int i = cur_i; i < occupancy_estimate; i++) {
    //         wait_times[cur_i] = 0;
    //         num_filled_in += 1;
    //     }
    // }

    // ** for testing, log wait times of ble and wifi separate
    uint8_t ble_in_range_wait_times[get_in_range_ble_device_count()];
    int cur_i_ble_in_range = 0;
    uint8_t ble_covid_wait_times[get_covid_exposure_ble_device_count()];
    int cur_i_ble_covid = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = ble_detected_devices.get(i).rssi >= BLE_RSSI_THRESHOLD;
        bool been_around = millis() - ble_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = ble_detected_devices.get(i).time_last_detected >= ble_scan_start_time;

        int time_around = ble_detected_devices.get(i).time_last_detected - ble_detected_devices.get(i).time_first_detected;

        // in range
        if (pass_rssi && been_around && seen_in_last_scan) {
            ble_in_range_wait_times[cur_i_ble_in_range] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_ble_in_range += 1;
        }

        // covid device
        if (ble_detected_devices.get(i).advertising_covid_exposure && been_around && seen_in_last_scan) {
            ble_covid_wait_times[cur_i_ble_covid] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_ble_covid += 1;
        }
    }

    uint8_t wifi_in_range_wait_times[get_in_range_wifi_device_count()];
    int cur_i_wifi_in_range = 0;
    uint8_t wifi_important_wait_times[get_important_wifi_device_count()];
    int cur_i_wifi_important = 0;
    uint8_t wifi_not_not_important_wait_times[get_not_not_important_wifi_device_count()];
    int cur_i_wifi_not_not_important = 0;
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = wifi_detected_devices.get(i).rssi >= WIFI_RSSI_THRESHOLD;
        if (wifi_detected_devices.get(i).oui == unknown) {
            // unknown devices have to pass a higher RSSI threshold to be considered in range
            pass_rssi = wifi_detected_devices.get(i).rssi >= -65;
        }
        bool been_around = millis() - wifi_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;

        int time_around = wifi_detected_devices.get(i).time_last_detected - wifi_detected_devices.get(i).time_first_detected;
                
        if (pass_rssi && been_around && seen_in_last_scan) {
            wifi_in_range_wait_times[cur_i_wifi_in_range] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_wifi_in_range += 1;
        }

        if (wifi_detected_devices.get(i).oui == important && seen_in_last_scan) {
            wifi_important_wait_times[cur_i_wifi_important] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_wifi_important += 1;
        }

        if (wifi_detected_devices.get(i).oui == not_important && pass_rssi && been_around && seen_in_last_scan) {
            wifi_not_not_important_wait_times[cur_i_wifi_not_not_important] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i_wifi_not_not_important += 1;
        }
    }

    Serial.print("BLE In Range Wait Times = ");
    for (int i = 0; i < cur_i_ble_in_range; i++) {
        Serial.printf("%d, ", ble_in_range_wait_times[i]);
    }
    Serial.println();

    Serial.print("BLE Covid Wait Times = ");
    for (int i = 0; i < cur_i_ble_covid; i++) {
        Serial.printf("%d, ", ble_covid_wait_times[i]);
    }
    Serial.println();

    Serial.print("Wi-Fi In Range Wait Times = ");
    for (int i = 0; i < cur_i_wifi_in_range; i++) {
        Serial.printf("%d, ", wifi_in_range_wait_times[i]);
    }
    Serial.println();

    Serial.print("Wi-Fi Important Wait Times = ");
    for (int i = 0; i < cur_i_wifi_important; i++) {
        Serial.printf("%d, ", wifi_important_wait_times[i]);
    }
    Serial.println();

    Serial.print("Wi-Fi Not Not Important Wait Times = ");
    for (int i = 0; i < cur_i_wifi_not_not_important; i++) {
        Serial.printf("%d, ", wifi_not_not_important_wait_times[i]);
    }
    Serial.println();

    // log occupancy metrics to serial monitor
    // Serial.print("Occupancy Over Time = ");
    // for (int i = 0; i <= current_i; i++) {
    //     Serial.printf("%d, ", occupancy_metrics[i]);
    // }
    // Serial.println();

    // log wait time metrics to serial monitor
    // Serial.print("Current Wait Times = ");
    // for (int i = 0; i < occupancy_estimate; i++) {
    //     Serial.printf("%d, ", wait_times[i]);
    // }
    // Serial.println();

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("[TIME=%0.3f, OCCUPANCY=%d, ", current_time/(60.0*1000.0), occupancy_metrics[current_i]);

        // Serial.print("WAIT_TIMES=");
        // for (int i = 0; i < total_devices; i++) {
        //     Serial.printf("%d,", wait_times[i]);
        // }
        Serial.println("]");
    }

    if (logMacAddrSeen) {
        int ble_scan_time = ble_scan_start_time - start_time;
        Serial.printf("BLE MAC ADDR, %0.3f = [", ble_scan_time/(60.0*1000.0));
        for (int i = 0; i < ble_detected_devices.size(); i++) {
            Serial.print("(");
            Serial.print(ble_detected_devices.get(i).time_first_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(ble_detected_devices.get(i).time_last_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(ble_detected_devices.get(i).mac_addr.c_str());
            Serial.print(",");
            Serial.print(ble_detected_devices.get(i).rssi);
            Serial.print(",");
            Serial.print(ble_detected_devices.get(i).advertising_covid_exposure);
            Serial.print("),");
        }
        Serial.println("]");
        int wifi_scan_time = wifi_scan_start_time - start_time;
        Serial.printf("WIFI MAC ADDR, %0.3f = [", wifi_scan_time/(60.0*1000.0));
        for (int i = 0; i < wifi_detected_devices.size(); i++) {
            Serial.print("(");
            Serial.print(wifi_detected_devices.get(i).time_first_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).time_last_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).mac_addr.c_str());
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).rssi);
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).wifi_channel);
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).pckt_addr_num);
            Serial.print("),");
        }
        Serial.println("]");
    }
    
    current_i = current_i + 1;
}

void ble_scan_devices() {
    ble_scan_start_time = millis();

    // Clear out devices that haven't been seen recently
    clear_old_devices();
    
    // Init BLE device
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("*[TIME=%0.3f, DEVICES_FOUND=%d, DEVICES_STORED=%d, IN_RANGE_COUNT=%d, COVID_COUNT=%d]\n", current_time / (60.0*1000.0), foundDevices.getCount(), ble_detected_devices.size(), get_in_range_ble_device_count(), get_covid_exposure_ble_device_count());
    }

    // Delete results fromBLEScan buffer to release memory
    pBLEScan->clearResults();   
    // Deinit BLE device
    BLEDevice::deinit();
}

int get_in_range_ble_device_count() {
    int count = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = ble_detected_devices.get(i).rssi >= BLE_RSSI_THRESHOLD;
        bool been_around = millis() - ble_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = ble_detected_devices.get(i).time_last_detected >= ble_scan_start_time;
        if (pass_rssi && been_around && seen_in_last_scan) {
            count += 1;
        }
    }
    return count;
}

int get_covid_exposure_ble_device_count() {
    int count = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        bool been_around = millis() - ble_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = ble_detected_devices.get(i).time_last_detected >= ble_scan_start_time;
        if (ble_detected_devices.get(i).advertising_covid_exposure && been_around && seen_in_last_scan) {
            count += 1;
        }
    }
    return count;
}

bool device_seen_before(std::string addr, int rssi) {
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (ble_detected_devices.get(i).mac_addr.compare(addr) == 0) {
            // Update time last detected and rssi
            DetectedDevice device = ble_detected_devices.get(i);
            device.time_last_detected = millis();
            device.rssi = rssi;
            ble_detected_devices.set(i, device);
            return true;
        }
    }
    return false;
}

void clear_old_devices() {
    int removed_count = 0;
    // Remove devices that haven't been seen for greater than DEVICE_TIMEOUT
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (millis() - ble_detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            ble_detected_devices.remove(i);
            removed_count += 1;
        }
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

    if (logWifiMacAddr) {
        // Serial.printf("[%d]-[", current_i);
        // Serial.print(mac_addr.c_str());
        // Serial.print("]-[");
        // Serial.print(destination_addr.c_str());
        // Serial.print("]-[");
        // Serial.print(channel);
        // Serial.print("]-[");
        // Serial.print(ppkt->payload)
        // Serial.println("]");

        int current_time = millis() - start_time;
        printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
		" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
		" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x,TIME=%0.3f\n",
		wifi_sniffer_packet_type2str(type),
		ppkt->rx_ctrl.channel,
		ppkt->rx_ctrl.rssi,
		/* ADDR1 */
		hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
		hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
		/* ADDR2 */
		hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
		hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
		/* ADDR3 */
		hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
		hdr->addr3[3],hdr->addr3[4],hdr->addr3[5], current_time/(60.0*1000.0));
        delay(10);
    }

    // Looks at sender address in packet
    if (mac_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !sniffed_device_before(mac_addr, ppkt->rx_ctrl.rssi)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = mac_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(mac_addr);

        // ** for testing purposes
        newDevice.wifi_channel = ppkt->rx_ctrl.channel;
        newDevice.pckt_addr_num = 2;

        wifi_detected_devices.add(newDevice);
    }

    // Looks at sender address in packet
    if (destination_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !sniffed_device_before(destination_addr, ppkt->rx_ctrl.rssi)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = destination_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(destination_addr);

        // ** for testing purposes
        newDevice.wifi_channel = ppkt->rx_ctrl.channel;
        newDevice.pckt_addr_num = 1;

        wifi_detected_devices.add(newDevice);
    }

    // Looks at sender address in packet
    if (filtering_addr.compare("ff:ff:ff:ff:ff:ff") != 0 && !sniffed_device_before(filtering_addr, ppkt->rx_ctrl.rssi)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        DetectedDevice newDevice;
        newDevice.mac_addr = filtering_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        newDevice.oui = get_mac_addr_oui_class(filtering_addr);

        // ** for testing purposes
        newDevice.wifi_channel = ppkt->rx_ctrl.channel;
        newDevice.pckt_addr_num = 3;

        wifi_detected_devices.add(newDevice);
    }
}

void wifi_sniff() {
    wifi_scan_start_time = millis();

    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_wifi_devices();

    // * for testing purposes
    wifi_devices_seen = 0;
    channel = 1;

    // Init Wi-Fi Sniffer
    wifi_sniffer_init();

    // Perform wifi sniffing for 2.5 seconds per channel, 12 channels -> 30 seconds total
    // TODO: explore in beta, having more "popular" channels (1, 6, and 11) get more scanning time than others
    // uint8_t time_per_channel[12] = {3, 1, 1, 1, 1, 3, 1, 1, 1, 1, 3};
    for (int i = 1; i <= 11; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        channel = i;
        
        delay(1500);
        // delay(time_per_channel[i-1] * 1000);
    }
    ESP_ERROR_CHECK( esp_wifi_stop() );

    // Deinit Wi-Fi Sniffer
    ESP_ERROR_CHECK( esp_wifi_deinit() );

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("\n#[TIME=%0.3f, WIFI_TOTAL_COUNT=%d, DEVICES_STORED=%d", current_time/(60.0*1000.0), wifi_devices_seen, wifi_detected_devices.size());
        Serial.printf(", WIFI_IN_RANGE=%d, WIFI_DO_CARE=%d, WIFI_NOT_DO_NOT_CARE=%d]\n", get_in_range_wifi_device_count(), get_important_wifi_device_count(), get_not_not_important_wifi_device_count());
    }
}

int get_in_range_wifi_device_count() {
    int count = 0;
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        // for device to be considered in range, it must meet the RSSI threshold, have been around for more than 2.5 minutes, and seen recently
        bool pass_rssi = wifi_detected_devices.get(i).rssi >= WIFI_RSSI_THRESHOLD;
        if (wifi_detected_devices.get(i).oui == unknown) {
            // unknown devices have to pass a higher RSSI threshold to be considered in range
            pass_rssi = wifi_detected_devices.get(i).rssi >= -65;
        }
        bool been_around = millis() - wifi_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;
        if (pass_rssi && been_around && seen_in_last_scan) {
            count += 1;
        }
    }
    return count;
}

int get_important_wifi_device_count() {
    int count = 0;
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;
        if (wifi_detected_devices.get(i).oui == important && seen_in_last_scan) {
            count += 1;
        }
    }
    return count;
}

int get_not_not_important_wifi_device_count() {
    int count = 0;
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        bool pass_rssi = wifi_detected_devices.get(i).rssi >= WIFI_RSSI_THRESHOLD;
        if (wifi_detected_devices.get(i).oui == unknown) {
            pass_rssi = wifi_detected_devices.get(i).rssi >= -65;
        }
        bool been_around = millis() - wifi_detected_devices.get(i).time_first_detected >= 1000.0*60.0*2.5;
        bool seen_in_last_scan = wifi_detected_devices.get(i).time_last_detected >= wifi_scan_start_time;
        if (wifi_detected_devices.get(i).oui != not_important && pass_rssi && been_around && seen_in_last_scan) {
            count += 1;
        }
    }
    return count;
}

bool sniffed_device_before(std::string addr, int rssi) {
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        // TODO: check that adding c_str here didn't hurt anything
        if (wifi_detected_devices.get(i).mac_addr.compare(addr.c_str()) == 0) {
            // Update time last detected
            DetectedDevice device = wifi_detected_devices.get(i);
            device.time_last_detected = millis();
            device.rssi = rssi;
            wifi_detected_devices.set(i, device);
            return true;
        }
    }
    return false;
}

void clear_old_wifi_devices() {
    int removed_count = 0;
    // Remove devices that haven't been seen for greater than DEVICE_TIMEOUT
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        if (millis() - wifi_detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            wifi_detected_devices.remove(i);
            removed_count += 1;
        }
    }
}

bool is_mac_addr_oui_important(std::string mac_addr_oui) {
    // Serial.println("check if oui is important");
    // Serial.println(mac_addr_oui.c_str());
    for (int i = 0; i < IMPORTANT_MAC_OUIS_SIZE; i++) {
        // Serial.print("comparing with ");
        // Serial.println(important_mac_ouis[i].c_str());
        // Serial.println(important_mac_ouis[i].compare(mac_addr_oui));
        // Serial.println(important_mac_ouis[i].compare(mac_addr_oui.c_str()));
        // Serial.println(important_mac_ouis[i].c_str() == mac_addr_oui.c_str());
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
    Serial.print(mac_addr.c_str());
    Serial.print(",");
    if (is_mac_addr_oui_important(mac_addr)) {
        // Serial.println(" is important");
        return important;
    } else if (is_mac_addr_oui_not_important(mac_addr)) {
        // Serial.println(" is not important");
        return not_important;
    }
    // Serial.println();
    // Serial.println(" is unknown");
    return unknown;
}