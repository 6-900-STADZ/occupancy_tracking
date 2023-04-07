#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
// https://github.com/ivanseidel/LinkedList
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

// -- Button vars --

#define BUTTON_PIN 21
int lastState = HIGH;
int currentState;

// -- BLE vars --

// ESP32 docs - https://h2zero.github.io/esp-nimble-cpp/class_nim_b_l_e_advertised_device.html#ac1b8ff0f2897abda335743d55668fcd9
bool run_ble_continous = false;
bool scanning = false;
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
};
// DetectedDevice detected_devices[1000];
LinkedList<BLEDetectedDevice> detected_devices;

void ble_scan_devices();
int get_in_range_device_count();
bool device_seen_before(std::string addr);
void clear_old_devices();

// -- Wi-Fi vars --
// https://github.com/ESP-EOS/ESP32-WiFi-Sniffer/blob/master/WIFI_SNIFFER_ESP32.ino

bool run_wifi_sniff_continous = false;

int max_wifi_RSSI = 1;
int min_wifi_RSSI = 1;

class WiFiDetectedDevice {
  public:
    std::string wifi_mac_addr;
    int rssi;
    unsigned long time_last_detected;
};
// DetectedDevice detected_devices[1000];
LinkedList<WiFiDetectedDevice> sniffer_detected_devices;
unsigned long last_wifi_sniff_time;

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
        detected_devices.add(newDevice);

        // Serial.printf("%d. Advertised Device: %s \n", device_count, advertisedDevice.toString().c_str());

        // Serial.printf("Name: %s \n", advertisedDevice.getName().c_str());
        // Serial.printf("Addr: %s \n", advertisedDevice.getAddress().toString().c_str());
        // BLE_ADDR_PUBLIC (0x00), BLE_ADDR_RANDOM (0x01), BLE_ADDR_PUBLIC_ID (0x02), BLE_ADDR_RANDOM_ID (0x03)
        // Serial.printf("Address Type: %zu \n", (unsigned int)advertisedDevice.getAddressType());

        // For testing purposes, tracks the max and min RSSI seen
        if (advertisedDevice.getRSSI() > max_RSSI || max_RSSI == 1) {
            max_RSSI = advertisedDevice.getRSSI();
        }
        if (advertisedDevice.getRSSI() < min_RSSI || min_RSSI == 1) {
            min_RSSI = advertisedDevice.getRSSI();
        }

        if (advertisedDevice.haveName()) {
            Serial.print("Device name: ");
            Serial.println(advertisedDevice.getName().c_str());
        }
        // https://stackoverflow.com/questions/12120426/how-do-i-print-uint32-t-and-uint16-t-variables-value
        if (advertisedDevice.haveAppearance()) {
            char appearance_val[20];
            snprintf(appearance_val, sizeof(appearance_val), "Appearance: %d", advertisedDevice.getAppearance());
            Serial.println(appearance_val);
        }
        
        // ? could add member service id's to object, help say what company it is
        if (advertisedDevice.haveServiceUUID()) {
            std::string res = "";
            for (int i=0; i < advertisedDevice.getServiceUUIDCount(); i++) {
                res += ", serviceUUID: " + advertisedDevice.getServiceUUID(i).toString();
            }
            Serial.print("-- Service UUIDs --  ");
            Serial.println(res.c_str());
        }

        // uint8_t *payload = advertisedDevice.getPayload();
        // size_t payloadLength = advertisedDevice.getPayloadLength();

        // Serial.printf("Payload Length: %zu \n", payloadLength)
        // splits into length, adv type, value and then repeats until payload ends
        // Serial.print("Payload: ");
        // for (int i=0; i<payloadLength; i++) {
        //     Serial.printf("%02x", payload[i]);
        // }
        // Serial.println();

        // Can be used to check if a particular service is being advertised
        BLEUUID ble_exposure_notification_uuid = BLEUUID("0000fd6f-0000-1000-8000-00805f9b34fb");
        if (advertisedDevice.isAdvertisingService(ble_exposure_notification_uuid)) {
            Serial.println("advertising covid exposure notification service");
        }

    }
};

void setup() {
    Serial.begin(115200);
    delay(100);

    Serial.println("Scanning...");
    last_wifi_sniff_time = millis();

    run_wifi_sniff_continous = true;

    // initialize the pushbutton pin as an pull-up input
    pinMode(BUTTON_PIN, INPUT_PULLUP);

    // Initializes the ESP32 as a BLE device
    // BLEDevice::init("");
    // pBLEScan = BLEDevice::getScan(); //create new scan
    // pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    // pBLEScan->setActiveScan(false); //active scan uses more power, but get results faster
    // pBLEScan->setInterval(100); 
    // pBLEScan->setWindow(99);  // less or equal setInterval value

    // Initializes Wi-Fi Sniffer
    delay(10);
    wifi_sniffer_init();
}

void loop() {
    // Serial.print("inside loop");
    // delay(1000); // wait for a second
    
    bool button_pressed = false;
    currentState = digitalRead(BUTTON_PIN);
    if(lastState == LOW && currentState == HIGH && scanning == false) {
        Serial.println("button pressed");
        button_pressed = true;
    }
    lastState = currentState;

    if (run_wifi_sniff_continous) {
        // Perform wifi sniffing every 3 minutes
        if (millis() - last_wifi_sniff_time > 1000*60*3) {
            last_wifi_sniff_time = millis();
            wifi_sniff();
        }
    } else if (button_pressed) {
        // Perform wifi sniffing every time the button is pressed
        wifi_sniff();
    }

    // if (run_ble_continous) {
    //     // Scan every 30 seconds
    //     ble_scan_devices();
    //     delay(1000 * 30); // TODO: change to be non-blocking
    // } else {
    //     // Scan when button is pressed
    //     currentState = digitalRead(BUTTON_PIN);
    //     if(lastState == LOW && currentState == HIGH && scanning == false) {
    //         ble_scan_devices();
    //     }
    //     lastState = currentState;
    // }

}

void ble_scan_devices() {
    // put your main code here, to run repeatedly:
    scanning = true;

    // Clear out devices that haven't been seen recently
    clear_old_devices();

    Serial.println("Starting scan... ");
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
    // Serial.print("\nDevices found: ");
    // Serial.println(foundDevices.getCount());
    pBLEScan->clearResults();   // delete results fromBLEScan buffer to release memory

    Serial.print("\nMax RSSI: ");
    Serial.print(max_RSSI);
    Serial.print("  --  Min RSSI: ");
    Serial.print(min_RSSI);
    Serial.print("  --  In Range Device Count: ");
    Serial.printf("%d, %d\n", get_in_range_device_count(), detected_devices.size());
    Serial.println("Scan done!");
    scanning = false;
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

bool device_seen_before(std::string addr) {
    for (int i = 0; i < detected_devices.size(); i++) {
        if (detected_devices.get(i).ble_mac_addr.compare(addr) == 0) {
            // Update time last detected
            BLEDetectedDevice device = detected_devices.get(i);
            device.time_last_detected = millis();
            return true;
        }
    }
    return false;
}

void clear_old_devices() {
    for (int i = 0; i < detected_devices.size(); i++) {
        // If device not seen in the last minute, remove it
        if (millis() - detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            Serial.println("cleared an old device");
            detected_devices.remove(i);
        }
    }
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
//   esp_wifi_set_promiscuous(true); // appears to turn on the wifi scanning
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
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

// TODO: Clear out old devices from detected devices list
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
    // be:d7:d4:e4:81:9�␞�?␁

    // Looks at sender address in packet
    if (sniffed_device_before(mac_addr)) {
        // Serial.println("device seen before");
        return;
    }

    // For testing purposes, tracks the max and min RSSI seen
    if (ppkt->rx_ctrl.rssi > max_wifi_RSSI || max_wifi_RSSI == 1) {
        max_wifi_RSSI = ppkt->rx_ctrl.rssi;
    }
    if (ppkt->rx_ctrl.rssi < min_wifi_RSSI || min_wifi_RSSI == 1) {
        min_wifi_RSSI = ppkt->rx_ctrl.rssi;
    }

    // only log new found mac devices
    // printf("from addr2 PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
    // " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
    // " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
    // " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
    // wifi_sniffer_packet_type2str(type),
    // ppkt->rx_ctrl.channel,
    // ppkt->rx_ctrl.rssi,
    // /* ADDR1 */
    // hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    // hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
    // /* ADDR2 */
    // hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    // hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    // /* ADDR3 */
    // hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    // hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
    // );

    // Add new detected device to linked list
    WiFiDetectedDevice newDevice;
    newDevice.wifi_mac_addr = mac_addr;
    newDevice.rssi = ppkt->rx_ctrl.rssi;
    newDevice.time_last_detected = millis();
    sniffer_detected_devices.add(newDevice);
}

void wifi_sniff() {
    // Clear out old devices detected from wifi scanning that haven't been seen recently
    clear_old_wifi_devices();

    // Perform wifi sniffing for 3 seconds per channel
    esp_wifi_set_promiscuous(true);

    for (int i = 1; i < WIFI_CHANNEL_MAX; i++) {
        vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
        wifi_sniffer_set_channel(i);
        // channel = (channel % WIFI_CHANNEL_MAX) + 1;

        delay(3000);
    }

    esp_wifi_set_promiscuous(false);

    Serial.print("\nMax Wifi RSSI: ");
    Serial.print(max_wifi_RSSI);
    Serial.print("  --  Min Wifi RSSI: ");
    Serial.print(min_wifi_RSSI);
    Serial.print("  --  Wifi In Range Device Count: ");
    Serial.printf("%d, %d\n", get_in_range_wifi_device_count(), sniffer_detected_devices.size());
    Serial.println("Scan done!");
    scanning = false;
}

bool sniffed_device_before(std::string addr) {
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        if (sniffer_detected_devices.get(i).wifi_mac_addr.compare(addr) == 0) {
            // Update time last detected
            WiFiDetectedDevice device = sniffer_detected_devices.get(i);
            device.time_last_detected = millis();
            return true;
        }
    }
    return false;
}

void clear_old_wifi_devices() {
    for (int i = 0; i < sniffer_detected_devices.size(); i++) {
        // If device not seen in the last minute, remove it
        if (millis() - sniffer_detected_devices.get(i).time_last_detected > DEVICE_TIMEOUT) {
            Serial.println("cleared an old device");
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