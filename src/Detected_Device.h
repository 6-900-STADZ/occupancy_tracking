#ifndef DETECTED_DEVICE_H
#define DETECTED_DEVICE_H

#include <Arduino.h>

class DetectedDevice {
  
  private:
    std::string mac_addr;
    int rssi;
    unsigned long time_first_detected;
    unsigned long time_last_detected;
    bool advertising_covid_exposure;
    
  public:

    // Setup device
    void init(std::string mac_addr, int rssi, bool advertising_covid_exposure);

    // Update the last time this device was detected
    void update_last_time_detected();

    // Calculate the time this device has been detected being around
    int get_time_around();

    // Return device's mac address
    std::string get_mac_addr();
    
    // Return device's last time detected
    unsigned long get_time_last_detected();

    // Return device's RSSI
    int get_rssi();

    // Returns true if device is advertising the covid exposure notification
    bool is_advertising_covid_exposure();
};

#endif