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

// if a device hasn't been seen for greater than DEVICE_TIMEOUT, clear it
#define DEVICE_TIMEOUT          (1000*60*4) 
// device is considered "in range" if it's RSSI is at or above this
#define BLE_RSSI_THRESHOLD            (-50) 
#define WIFI_RSSI_THRESHOLD           (-55)
// scan to check occupancy every 1 minute
#define SCANNING_TIME           (1000*60*3) // TODO: change to 3 minutes later, keep as 1 for testing

// TODO: explore in beta, if we need to remove devices seen for too long

unsigned long last_scan_time;
void update_detected_devices();

// enough for 12 hours of data, with a little extra room
int current_i = 0;
int occupancy_metrics[250]; // 250 leaves enough space for a full day of occupancy data

// RSSI (Received signal strength indication): measured in decibels from 0 (zero) to -120 (minus 120)
// closer to 0 (zero) the stronger the signal, which means it's better
int max_RSSI = 1;
int min_RSSI = 1;
int channel = 0;
bool logOccupancy = true;
bool logWifiMacAddr = false;
bool logBLEMacAddr = false;
bool logMacAddrSeen = false;
unsigned long start_time;
unsigned long ble_scan_start_time;
unsigned long wifi_scan_start_time;
int ble_detected_count = 0;
int wifi_detected_count = 0;

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
int scanTime = 1; // seconds
BLEScan* pBLEScan;

// TODO: move to be its own file
// TODO: might combine with WiFIDetectedDevice to be one class, with property of detected_by maybe
class BLEDetectedDevice {
  public:
    std::string ble_mac_addr;
    int rssi;
    unsigned long time_first_detected;
    unsigned long time_last_detected;
    bool advertising_covid_exposure;
};
// stores detected devices within BLE_RSSI_THRESHOLD
LinkedList<BLEDetectedDevice> ble_detected_devices;

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
LinkedList<WiFiDetectedDevice> wifi_detected_devices;

void wifi_sniff();
void clear_old_wifi_devices();
bool sniffed_device_before(std::string addr);

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

        // TODO: explore in beta, bringing this back but we need to account for them having much lower RSSI's -80 to -95
        BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");
        // if (advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid)) {
        //     Serial.printf("advertising covid with RSSI %d", advertisedDevice.getRSSI());
        // }

        // * For testing purposes, tracks the max and min RSSI seen
        if (advertisedDevice.getRSSI() > max_RSSI || max_RSSI == 1) {
            max_RSSI = advertisedDevice.getRSSI();
        }
        if (advertisedDevice.getRSSI() < min_RSSI || min_RSSI == 1) {
            min_RSSI = advertisedDevice.getRSSI();
        }

        if (device_seen_before(strAddrData) == true || (advertisedDevice.getRSSI() < BLE_RSSI_THRESHOLD && !advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid))) {
        // if (device_seen_before(strAddrData) == true || advertisedDevice.getRSSI() < BLE_RSSI_THRESHOLD) {
            // don't store device RSSI is too low or it's already stored
            return;
        }

        BLEDetectedDevice newDevice;
        newDevice.ble_mac_addr = strAddrData;
        newDevice.rssi = advertisedDevice.getRSSI();

        // TODO: does millis reset after going into sleep overnight
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;

        if (logBLEMacAddr) {
            Serial.print("*[BLE_ADDR=");
            Serial.print(strAddrData.c_str());
            Serial.println("]");
        }
        
        // Can be used to check if a particular service is being advertised
        // BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");
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

    // Sniff Wi-Fi traffic
    wifi_sniff();

    // Average numbers to decide on bus stop occupancy at this time
    float wifi_factor = 0.8 * wifi_detected_devices.size(); // pulls average down to help accoutn for people with multiple devices  
    float ble_factor = 0.5 * get_in_range_ble_device_count(); // pulls average down to help accoutn for people with multiple devices 

    // TODO: might explore in beta using this factor again in beta, but we need to account for that RSSI's tend to be low -80 to -95
    // ? maybe only use ble for covid count
    // float ble_covid_factor = 0.5 * get_in_covid_exposure_ble_device_count();  
    // int occupancy_estimate = (wifi_factor + ble_factor + ble_covid_factor) / 3;

    int occupancy_estimate = (wifi_factor + ble_factor) / 2;

    // save the current believed “occupancy”
    occupancy_metrics[current_i] = occupancy_estimate;

    // wait time buckets - [(3, x), (6, y), ...]
    // modulo time around by 3 ?
    // TODO: should this be done server-side ? send the whole list of wait times rounded to units of 3 and not including the 0s

    // Store current wait times rounded to nearest 0, 3, 6 min, etc.
    int total_devices = get_in_range_ble_device_count() + wifi_detected_devices.size();
    int wait_times[total_devices];

    int cur_i = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (ble_detected_devices.get(i).rssi >= BLE_RSSI_THRESHOLD) {
            int time_around = ble_detected_devices.get(i).time_last_detected - ble_detected_devices.get(i).time_first_detected;
            wait_times[cur_i] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
            cur_i += 1;
        }
    }

    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        int time_around = wifi_detected_devices.get(i).time_last_detected - wifi_detected_devices.get(i).time_first_detected;
        wait_times[i + get_in_range_ble_device_count()] = (time_around / (60.0*1000.0)) + 0.5; // plus 0.5 is for rounding
    }

    // log occupancy metrics to serial monitor
    // Serial.print("Occupancy Over Time = ");
    // for (int i = 0; i <= current_i; i++) {
    //     Serial.printf("%d, ", occupancy_metrics[i]);
    // }
    // Serial.println();


    // log wait time metrics to serial monitor
    // Serial.print("Current Wait Times = ");
    // for (int i = 0; i < total_devices; i++) {
    //     Serial.printf("%0.2f, ", wait_times[i]);
    //     // Serial.printf("%d, ", wait_times[i]);
    // }
    // Serial.println();

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("[TIME=%0.3f,OCCUPANCY=%d,", current_time/(60.0*1000.0), occupancy_metrics[current_i]);

        Serial.print("WAIT_TIMES=");
        for (int i = 0; i < total_devices; i++) {
            Serial.printf("%d,", wait_times[i]);
        }
        Serial.println("]");
    }

    if (logMacAddrSeen) {
        int ble_scan_time = ble_scan_start_time - start_time;
        Serial.printf("BLE MAC ADDR, %0.3f = [", ble_scan_time/(60.0*1000.0));
        for (int i = 0; i < ble_detected_devices.size(); i++) {
            Serial.print("(");
            Serial.print(ble_detected_devices.get(i).time_last_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(ble_detected_devices.get(i).ble_mac_addr.c_str());
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
            Serial.print(wifi_detected_devices.get(i).time_last_detected/(60.0*1000.0));
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).wifi_mac_addr.c_str());
            Serial.print(",");
            Serial.print(wifi_detected_devices.get(i).rssi);
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
    // // TODO: temporary, testing without device timeout to clear instead each iteration reset wifi_detected_devices to empty list
    // for (int i = 0; i < ble_detected_devices.size(); i++) {
    //     ble_detected_devices.pop();
    // }
    // ble_detected_devices.clear();
    // Serial.print("checking size of cleared list = ");
    // Serial.println(ble_detected_devices.size());
    
    // Init BLE device
    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());

    max_RSSI = 1;
    min_RSSI = 1;

    // Serial.println("Starting scan... ");
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
    // Serial.printf("BLE Devices found: %d", foundDevices.getCount());

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("*[TIME=%0.3f, TOTAL_COUNT=%d, MAX_RSSI=%d, MIN_RSSI=%d, IN_RANGE_COUNT=%d, COVID_COUNT=%d]\n", current_time / (60.0*1000.0), foundDevices.getCount(), max_RSSI, min_RSSI, get_in_range_ble_device_count(), get_in_covid_exposure_ble_device_count());
    }

    pBLEScan->clearResults();   // delete results fromBLEScan buffer to release memory

    
    // Deinit BLE device
    BLEDevice::deinit();

    // Serial.printf(", RSSI: %d to %d, In Range Count: %d, Covid Count: %d\n", max_RSSI, min_RSSI, get_in_range_ble_device_count(), get_in_covid_exposure_ble_device_count());
}

int get_in_range_ble_device_count() {
    // return ble_detected_devices.size();
    int count = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (ble_detected_devices.get(i).rssi >= BLE_RSSI_THRESHOLD) {
            count += 1;
        }
    }
    return count;
}

int get_in_covid_exposure_ble_device_count() {
    int count = 0;
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (ble_detected_devices.get(i).advertising_covid_exposure) {
            count += 1;
        }
    }
    return count;
}

bool device_seen_before(std::string addr) {
    for (int i = 0; i < ble_detected_devices.size(); i++) {
        if (ble_detected_devices.get(i).ble_mac_addr.compare(addr) == 0) {
            // Update time last detected
            BLEDetectedDevice device = ble_detected_devices.get(i);
            device.time_last_detected = millis();
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

    // * For testing purposes, tracks the max and min RSSI seen
    if (ppkt->rx_ctrl.rssi > max_RSSI || max_RSSI == 1) {
        max_RSSI = ppkt->rx_ctrl.rssi;
    }
    if (ppkt->rx_ctrl.rssi < min_RSSI || min_RSSI == 1) {
        min_RSSI = ppkt->rx_ctrl.rssi;
    }

    // Looks at sender address in packet
    if (!sniffed_device_before(mac_addr)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        WiFiDetectedDevice newDevice;
        newDevice.wifi_mac_addr = mac_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        wifi_detected_devices.add(newDevice);
    }

    // Looks at sender address in packet
    if (!sniffed_device_before(destination_addr)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        WiFiDetectedDevice newDevice;
        newDevice.wifi_mac_addr = destination_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        wifi_detected_devices.add(newDevice);
    }

    // Looks at sender address in packet
    if (!sniffed_device_before(filtering_addr)) {
        // * For testing purposes to see how many devices are being sniffed
        wifi_devices_seen += 1;

        if (ppkt->rx_ctrl.rssi < WIFI_RSSI_THRESHOLD) {
            // don't store device if above the top rssi threshold
            return;
        }

        // Add new detected device to linked list
        WiFiDetectedDevice newDevice;
        newDevice.wifi_mac_addr = filtering_addr;
        newDevice.rssi = ppkt->rx_ctrl.rssi;
        newDevice.time_first_detected = millis();
        newDevice.time_last_detected = newDevice.time_first_detected;
        wifi_detected_devices.add(newDevice);
    }
}

void wifi_sniff() {
    wifi_scan_start_time = millis();

    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_wifi_devices();
    // TODO: temporary, testing without device timeout to clear instead each iteration reset wifi_detected_devices to empty list
    // for (int i = 0; i < wifi_detected_devices.size(); i++) {
    //     wifi_detected_devices.pop();
    //     // TODO: might move away from linked list implementation
    //     // wifi_detected_devices.get(i)
    // }
    // wifi_detected_devices.clear();
    // Serial.print("checking size of cleared list = ");
    // Serial.println(wifi_detected_devices.size());

    // * for testing purposes
    max_RSSI = 1;
    min_RSSI = 1;
    wifi_devices_seen = 0;
    channel = 1;

    // Init Wi-Fi Sniffer
    wifi_sniffer_init();

    // Perform wifi sniffing for 2.5 seconds per channel, 12 channels -> 30 seconds total
    // TODO: explore in beta, having more "popular" channels get more scanning time than others
    for (int i = 1; i < WIFI_CHANNEL_MAX; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        channel = i;
        
        // delay(2500);
        delay(1500);
        // Serial.printf("device count after channel %d = %d\n", i, wifi_devices_seen);
    }
    ESP_ERROR_CHECK( esp_wifi_stop() );

    // Deinit Wi-Fi Sniffer
    ESP_ERROR_CHECK( esp_wifi_deinit() );

    // Serial.printf("Wi-Fi Devices found: %d, RSSI: %d to %d, In Range Count: %d\n", wifi_devices_seen, max_RSSI, min_RSSI, wifi_detected_devices.size());

    if (logOccupancy) {
        int current_time = millis() - start_time;
        Serial.printf("#[TIME=%0.3f, WIFI_TOTAL_COUNT=%d, MAX_RSSI=%d, MIN_RSSI=%d, IN_RANGE_COUNT=%d]\n", current_time/(60.0*1000.0), wifi_devices_seen, max_RSSI, min_RSSI, wifi_detected_devices.size());
    }
}

bool sniffed_device_before(std::string addr) {
    for (int i = 0; i < wifi_detected_devices.size(); i++) {
        if (wifi_detected_devices.get(i).wifi_mac_addr.compare(addr) == 0) {
            // Update time last detected
            WiFiDetectedDevice device = wifi_detected_devices.get(i);
            device.time_last_detected = millis();
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