#include "Detected_Device.h"

void DetectedDevice::init(std::string mac_addr, int rssi, bool advertising_covid_exposure) {
    mac_addr = mac_addr;
    rssi = rssi;

    unsigned long current_time = millis();
    time_first_detected = current_time;
    time_last_detected = current_time;

    advertising_covid_exposure = advertising_covid_exposure;
}

void DetectedDevice::update_last_time_detected() {
    // TODO: does millis reset after going into sleep overnight
    time_last_detected = millis();
}

int DetectedDevice::get_time_around() {
    return time_last_detected - time_first_detected;
}

std::string DetectedDevice::get_mac_addr() {
    return mac_addr;
}

int DetectedDevice::get_rssi() {
    return rssi;
}

unsigned long DetectedDevice::get_time_last_detected() {
    return time_last_detected;
}

bool DetectedDevice::is_advertising_covid_exposure() {
    return advertising_covid_exposure;
}